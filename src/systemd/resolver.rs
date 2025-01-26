//! Resolver code that finds options compatible with program actions

use std::path::PathBuf;

use crate::{
    cl::HardeningOptions,
    summarize::{NetworkActivity, ProgramAction},
    systemd::options::{
        ListMode, OptionDescription, OptionEffect, OptionValue, OptionValueEffect, OptionWithValue,
    },
};

use super::{
    options::{merge_similar_paths, OptionUpdater},
    ListOptionValue,
};

impl OptionValueEffect {
    fn compatible(
        &self,
        action: &ProgramAction,
        prev_actions: &[ProgramAction],
        updater: Option<&OptionUpdater>,
        hardening_opts: &HardeningOptions,
    ) -> ActionOptionEffectCompatibility {
        let compatible = match self {
            OptionValueEffect::DenyAction(denied) => match denied {
                ProgramAction::NetworkActivity(denied) => {
                    if let ProgramAction::NetworkActivity(NetworkActivity {
                        af,
                        proto,
                        kind,
                        local_port,
                    }) = action
                    {
                        let af_match = denied.af.intersects(af);
                        let proto_match = denied.proto.intersects(proto);
                        let kind_match = denied.kind.intersects(kind);
                        let local_port_match = denied.local_port.intersects(local_port);
                        !af_match || !proto_match || !kind_match || !local_port_match
                    } else {
                        true
                    }
                }
                ProgramAction::WriteExecuteMemoryMapping
                | ProgramAction::SetRealtimeScheduler
                | ProgramAction::Wakeup
                | ProgramAction::MknodSpecial
                | ProgramAction::SetAlarm => action != denied,
                ProgramAction::Syscalls(_)
                | ProgramAction::Read(_)
                | ProgramAction::Write(_)
                | ProgramAction::Create(_) => unreachable!(),
            },
            OptionValueEffect::DenyWrite(ro_paths) => match action {
                ProgramAction::Write(path_action) | ProgramAction::Create(path_action) => {
                    !ro_paths.matches(path_action)
                }
                _ => true,
            },
            OptionValueEffect::Hide(hidden_paths) => {
                if let ProgramAction::Read(path_action) = action {
                    !hidden_paths.matches(path_action)
                        || prev_actions.contains(&ProgramAction::Create(path_action.clone()))
                } else {
                    true
                }
            }
            OptionValueEffect::DenySyscalls(denied) => {
                if let ProgramAction::Syscalls(syscalls) = action {
                    let denied_syscalls = denied.syscalls();
                    let syscalls = syscalls.iter().map(String::as_str).collect();
                    denied_syscalls.intersection(&syscalls).next().is_none()
                } else {
                    true
                }
            }
            OptionValueEffect::Multiple(effects) => effects.iter().all(|e| {
                match e.compatible(action, prev_actions, None, hardening_opts) {
                    ActionOptionEffectCompatibility::Compatible => true,
                    ActionOptionEffectCompatibility::CompatibleIfChanged(_) => todo!(),
                    ActionOptionEffectCompatibility::Incompatible => false,
                }
            }),
        };
        if compatible {
            ActionOptionEffectCompatibility::Compatible
        } else if let Some(updater) = updater {
            if let Some(new_eff) = (updater.effect)(self, action, hardening_opts) {
                ActionOptionEffectCompatibility::CompatibleIfChanged(
                    ChangedOptionValueDescription {
                        new_options: (updater.options)(&new_eff, hardening_opts),
                        effect: new_eff,
                    },
                )
            } else {
                ActionOptionEffectCompatibility::Incompatible
            }
        } else {
            ActionOptionEffectCompatibility::Incompatible
        }
    }
}

/// A systemd option value and its effect, altered from original
#[derive(Debug)]
pub(crate) struct ChangedOptionValueDescription {
    pub new_options: Vec<OptionWithValue<&'static str>>,
    pub effect: OptionValueEffect,
}

impl ChangedOptionValueDescription {
    fn merge(&mut self, other: &Self) {
        let mut to_append = Vec::with_capacity(other.new_options.len());
        for ooption in &other.new_options {
            let mut handled = false;
            for option in &mut self.new_options {
                handled = option.merge(ooption);
                if handled {
                    break;
                }
            }
            if !handled {
                to_append.push(ooption.clone());
            }
        }
        self.new_options.append(&mut to_append);
        self.effect.merge(&other.effect);
    }
}

/// How compatible is an action with an option effect?
pub(crate) enum ActionOptionEffectCompatibility {
    Compatible,
    CompatibleIfChanged(ChangedOptionValueDescription),
    Incompatible,
}

impl From<bool> for ActionOptionEffectCompatibility {
    fn from(value: bool) -> Self {
        if value {
            Self::Compatible
        } else {
            Self::Incompatible
        }
    }
}

fn actions_compatible(
    eff: &OptionValueEffect,
    actions: &[ProgramAction],
    updater: Option<&OptionUpdater>,
    hardening_opts: &HardeningOptions,
) -> ActionOptionEffectCompatibility {
    let mut changed_desc: Option<ChangedOptionValueDescription> = None;
    for i in 0..actions.len() {
        let cur_eff = changed_desc.as_ref().map_or(eff, |d| &d.effect);
        match cur_eff.compatible(&actions[i], &actions[..i], updater, hardening_opts) {
            ActionOptionEffectCompatibility::Compatible => {}
            ActionOptionEffectCompatibility::CompatibleIfChanged(new_desc) => {
                log::debug!(
                    "Option effect {:?} is incompatible with {:?}, changing effect to {:?}",
                    cur_eff,
                    actions[i],
                    new_desc.effect
                );
                changed_desc = Some(new_desc);
            }
            ActionOptionEffectCompatibility::Incompatible => {
                log::debug!(
                    "Option effect {:?} is incompatible with {:?}",
                    cur_eff,
                    actions[i]
                );
                return ActionOptionEffectCompatibility::Incompatible;
            }
        }
    }

    if let Some(new_desc) = changed_desc {
        ActionOptionEffectCompatibility::CompatibleIfChanged(new_desc)
    } else {
        ActionOptionEffectCompatibility::Compatible
    }
}

fn actions_compatible_list(
    opt_name: &'static str,
    list: &ListOptionValue,
    effects: &[OptionValueEffect],
    actions: &[ProgramAction],
    updater: Option<&OptionUpdater>,
    hardening_opts: &HardeningOptions,
) -> ActionOptionEffectCompatibility {
    debug_assert_eq!(list.values.len(), effects.len());
    let mut changed_desc: Option<ChangedOptionValueDescription> = None;
    let mut enabled_list_vals = Vec::new();
    let mut enabled_list_val_effects = Vec::new();
    for (list_val, list_val_eff) in list.values.iter().zip(effects.to_vec().iter_mut()) {
        let compatible = actions_compatible(list_val_eff, actions, updater, hardening_opts);
        let enable_opt_val = match list.mode {
            ListMode::WhiteList => {
                matches!(compatible, ActionOptionEffectCompatibility::Incompatible)
            }
            ListMode::BlackList => match compatible {
                ActionOptionEffectCompatibility::Compatible => true,
                ActionOptionEffectCompatibility::CompatibleIfChanged(new_desc) => {
                    if let Some(changed_desc) = changed_desc.as_mut() {
                        changed_desc.merge(&new_desc);
                    } else {
                        changed_desc = Some(new_desc);
                    }
                    false
                }
                ActionOptionEffectCompatibility::Incompatible => false,
            },
        };
        if enable_opt_val {
            enabled_list_vals.push(list_val.to_owned());
            enabled_list_val_effects.push(list_val_eff.to_owned());
        }
    }
    if enabled_list_vals.is_empty() && matches!(list.mode, ListMode::BlackList) {
        return ActionOptionEffectCompatibility::Incompatible;
    }
    if list.values != enabled_list_vals || changed_desc.is_some() {
        // Rebuild option with changed list
        let mut new_list_desc = ChangedOptionValueDescription {
            new_options: vec![OptionWithValue {
                name: opt_name,
                value: OptionValue::List(ListOptionValue {
                    values: enabled_list_vals,
                    ..list.to_owned()
                }),
            }],
            effect: OptionValueEffect::Multiple(enabled_list_val_effects),
        };
        if let Some(changed_desc) = changed_desc.as_mut() {
            new_list_desc.merge(changed_desc);
            *changed_desc = new_list_desc;
        } else {
            changed_desc = Some(new_list_desc);
        }
    }
    if let Some(changed_desc) = changed_desc {
        ActionOptionEffectCompatibility::CompatibleIfChanged(changed_desc)
    } else {
        ActionOptionEffectCompatibility::Compatible
    }
}

pub(crate) fn resolve(
    opts: &Vec<OptionDescription>,
    actions: &[ProgramAction],
    hardening_opts: &HardeningOptions,
) -> Vec<OptionWithValue<&'static str>> {
    let mut candidates = Vec::new();
    for opt in opts {
        // Options are in the less to most restrictive order,
        // so for non cumulative options, iterate from the end
        for opt_value_desc in opt.possible_values.iter().rev() {
            match &opt_value_desc.desc {
                OptionEffect::None => {
                    candidates.push(OptionWithValue {
                        name: opt.name,
                        value: opt_value_desc.value.clone(),
                    });
                    break;
                }
                OptionEffect::Simple(effect) => {
                    match actions_compatible(effect, actions, opt.updater.as_ref(), hardening_opts)
                    {
                        ActionOptionEffectCompatibility::Compatible => {
                            candidates.push(OptionWithValue {
                                name: opt.name,
                                value: opt_value_desc.value.clone(),
                            });
                            break;
                        }
                        ActionOptionEffectCompatibility::CompatibleIfChanged(opt_new_desc) => {
                            candidates.extend(opt_new_desc.new_options);
                            break;
                        }
                        ActionOptionEffectCompatibility::Incompatible => {}
                    }
                }
                OptionEffect::Cumulative(effects) => {
                    match &opt_value_desc.value {
                        OptionValue::List(lv) => {
                            match actions_compatible_list(
                                opt.name,
                                lv,
                                effects,
                                actions,
                                opt.updater.as_ref(),
                                hardening_opts,
                            ) {
                                ActionOptionEffectCompatibility::Compatible => {
                                    candidates.push(OptionWithValue {
                                        name: opt.name,
                                        value: opt_value_desc.value.clone(),
                                    });
                                    break;
                                }
                                ActionOptionEffectCompatibility::CompatibleIfChanged(
                                    opt_new_desc,
                                ) => {
                                    candidates.extend(opt_new_desc.new_options);
                                    break;
                                }
                                ActionOptionEffectCompatibility::Incompatible => {}
                            }
                        }
                        _ => unreachable!(),
                    };
                }
            }
        }
    }

    // Merge paths in compatible options
    for option in &mut candidates {
        if let OptionValue::List(ListOptionValue {
            values,
            mergeable_paths: true,
            ..
        }) = &mut option.value
        {
            *values = merge_similar_paths(
                values
                    .iter()
                    .map(PathBuf::from)
                    .collect::<Vec<_>>()
                    .as_slice(),
                hardening_opts.merge_paths_threshold,
            )
            .into_iter()
            .filter_map(|p| p.to_str().map(ToOwned::to_owned))
            .collect();
        }
    }

    candidates
}

#[expect(clippy::shadow_unrelated)]
#[cfg(test)]
mod tests {
    use super::*;

    use crate::{
        cl::HardeningOptions,
        systemd::{build_options, KernelVersion, SystemdVersion},
    };

    fn test_options(names: &[&str]) -> Vec<OptionDescription> {
        let sd_version = SystemdVersion::new(254, 0);
        let kernel_version = KernelVersion::new(6, 4, 0);
        build_options(&sd_version, &kernel_version, &HardeningOptions::safe())
            .unwrap()
            .into_iter()
            .filter(|o| names.contains(&o.name))
            .collect()
    }

    #[test]
    fn test_resolve_protect_system() {
        let _ = simple_logger::SimpleLogger::new().init();
        let hardening_opts = HardeningOptions::safe();

        let opts = test_options(&["ProtectSystem"]);

        let actions = vec![];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 1);
        assert_eq!(format!("{}", candidates[0]), "ProtectSystem=strict");

        let actions = vec![ProgramAction::Write("/sys/whatever".into())];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 1);
        assert_eq!(format!("{}", candidates[0]), "ProtectSystem=strict");

        let actions = vec![ProgramAction::Write("/var/cache/whatever".into())];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 1);
        assert_eq!(format!("{}", candidates[0]), "ProtectSystem=full");

        let actions = vec![ProgramAction::Write("/etc/plop.conf".into())];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 1);
        assert_eq!(format!("{}", candidates[0]), "ProtectSystem=true");

        let actions = vec![ProgramAction::Write("/usr/bin/false".into())];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 0);
    }

    #[test]
    fn test_resolve_protect_home() {
        let _ = simple_logger::SimpleLogger::new().init();
        let hardening_opts = HardeningOptions::safe();

        let opts = test_options(&["ProtectHome"]);

        let actions = vec![];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 1);
        assert_eq!(format!("{}", candidates[0]), "ProtectHome=tmpfs");

        let actions = vec![ProgramAction::Write("/home/user/data".into())];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 1);
        assert_eq!(format!("{}", candidates[0]), "ProtectHome=true");

        let actions = vec![ProgramAction::Read("/home/user/data".into())];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 1);
        assert_eq!(format!("{}", candidates[0]), "ProtectHome=read-only");

        let actions = vec![
            ProgramAction::Create("/home/user/data".into()),
            ProgramAction::Read("/home/user/data".into()),
        ];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 1);
        assert_eq!(format!("{}", candidates[0]), "ProtectHome=true");
    }

    #[test]
    fn test_resolve_private_tmp() {
        let _ = simple_logger::SimpleLogger::new().init();
        let hardening_opts = HardeningOptions::safe();

        let opts = test_options(&["PrivateTmp"]);

        let actions = vec![];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 1);
        assert_eq!(format!("{}", candidates[0]), "PrivateTmp=true");

        let actions = vec![ProgramAction::Write("/tmp/data".into())];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 1);
        assert_eq!(format!("{}", candidates[0]), "PrivateTmp=true");

        let actions = vec![ProgramAction::Read("/tmp/data".into())];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 0);

        let actions = vec![
            ProgramAction::Create("/tmp/data".into()),
            ProgramAction::Read("/tmp/data".into()),
        ];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 1);
        assert_eq!(format!("{}", candidates[0]), "PrivateTmp=true");
    }
}
