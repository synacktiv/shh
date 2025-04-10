//! Resolver code that finds options compatible with program actions

use std::path::PathBuf;

use super::{
    ListOptionValue,
    options::{OptionUpdater, merge_similar_paths},
};
use crate::{
    cl::HardeningOptions,
    summarize::{NetworkActivity, ProgramAction},
    systemd::options::{
        ListMode, OptionDescription, OptionEffect, OptionValue, OptionValueEffect, OptionWithValue,
    },
};

impl OptionValueEffect {
    fn compatible(
        &self,
        action: &ProgramAction,
        prev_actions: &[ProgramAction],
        updater: Option<&OptionUpdater>,
        hardening_opts: &HardeningOptions,
    ) -> ActionOptionEffectCompatibility {
        let compatible: Vec<bool> = match self {
            OptionValueEffect::DenyAction(denied) => match denied {
                ProgramAction::NetworkActivity(denied) => {
                    if let ProgramAction::NetworkActivity(NetworkActivity {
                        af,
                        proto,
                        kind,
                        local_port,
                        address,
                    }) = action
                    {
                        let af_match = denied.af.intersects(af);
                        let proto_match = denied.proto.intersects(proto);
                        let kind_match = denied.kind.intersects(kind);
                        let local_port_match = denied.local_port.intersects(local_port);
                        let addr_match = denied.address.intersects(address);
                        vec![
                            !af_match
                                || !proto_match
                                || !kind_match
                                || !local_port_match
                                || !addr_match,
                        ]
                    } else {
                        vec![true]
                    }
                }
                ProgramAction::Read(_)
                | ProgramAction::WriteExecuteMemoryMapping
                | ProgramAction::SetRealtimeScheduler
                | ProgramAction::Wakeup
                | ProgramAction::MknodSpecial
                | ProgramAction::SetAlarm
                | ProgramAction::MountToHost => vec![action != denied],
                ProgramAction::Syscalls(_)
                | ProgramAction::Write(_)
                | ProgramAction::Create(_)
                | ProgramAction::Exec(_) => {
                    // Handled via different effects, see below
                    unreachable!()
                }
            },
            OptionValueEffect::DenyWrite(ro_paths) => match action {
                ProgramAction::Write(path_action) | ProgramAction::Create(path_action) => {
                    vec![!ro_paths.matches(path_action)]
                }
                _ => vec![true],
            },
            OptionValueEffect::DenyExec(noexec_paths) => match action {
                ProgramAction::Exec(path_action) => vec![!noexec_paths.matches(path_action)],
                _ => vec![true],
            },
            OptionValueEffect::EmptyPath(empty_paths) => match action {
                ProgramAction::Read(path_action) | ProgramAction::Exec(path_action) => {
                    vec![
                        !empty_paths.matches(path_action, true)
                            || prev_actions.contains(&ProgramAction::Create(path_action.clone())),
                    ]
                }
                ProgramAction::Write(path_action) => {
                    vec![
                        !empty_paths.matches(path_action, false)
                            || prev_actions.contains(&ProgramAction::Create(path_action.clone())),
                    ]
                }
                ProgramAction::Create(path_action) => {
                    vec![
                        !empty_paths.matches(path_action, false)
                            || (!empty_paths.base_ro
                                && path_action.parent().is_some_and(|pap| {
                                    (pap == empty_paths.base)
                                        || prev_actions
                                            .contains(&ProgramAction::Create(pap.to_path_buf()))
                                })),
                    ]
                }
                _ => vec![true],
            },
            OptionValueEffect::RemovePath(removed_paths) => match action {
                ProgramAction::Read(path_action)
                | ProgramAction::Write(path_action)
                | ProgramAction::Exec(path_action)
                | ProgramAction::Create(path_action) => vec![!removed_paths.matches(path_action)],
                _ => vec![true],
            },
            OptionValueEffect::DenySyscalls(denied) => {
                if let ProgramAction::Syscalls(syscalls) = action {
                    let denied_syscalls = denied.syscalls();
                    let syscalls = syscalls.iter().map(String::as_str).collect();
                    vec![denied_syscalls.intersection(&syscalls).next().is_none()]
                } else {
                    vec![true]
                }
            }
            OptionValueEffect::Multiple(effects) => effects
                .iter()
                .map(
                    |e| match e.compatible(action, prev_actions, None, hardening_opts) {
                        ActionOptionEffectCompatibility::Compatible => true,
                        ActionOptionEffectCompatibility::CompatibleIfChanged(_) => unimplemented!(),
                        ActionOptionEffectCompatibility::Incompatible => false,
                    },
                )
                .collect(),
        };
        if compatible.iter().all(|c| *c) {
            ActionOptionEffectCompatibility::Compatible
        } else if let Some(updater) = updater {
            let mut changed_opt_desc = None;
            for (subeff, subeff_compatible) in self.iter().zip(compatible) {
                if subeff_compatible {
                    let newopt_desc = ChangedOptionValueDescription {
                        new_options: (updater.options)(subeff, hardening_opts),
                        effect: subeff.to_owned(),
                    };
                    changed_opt_desc = Some(changed_opt_desc.map_or_else(
                        || newopt_desc.clone(),
                        |mut prev: ChangedOptionValueDescription| {
                            prev.merge(&newopt_desc);
                            prev
                        },
                    ));
                } else if let Some(new_subeff) = (updater.effect)(subeff, action, hardening_opts) {
                    let newopt_desc = ChangedOptionValueDescription {
                        new_options: (updater.options)(&new_subeff, hardening_opts),
                        effect: new_subeff,
                    };
                    changed_opt_desc = Some(changed_opt_desc.map_or_else(
                        || newopt_desc.clone(),
                        |mut prev: ChangedOptionValueDescription| {
                            prev.merge(&newopt_desc);
                            prev
                        },
                    ));
                } else {
                    changed_opt_desc = None;
                    break;
                }
            }
            changed_opt_desc.map_or(
                ActionOptionEffectCompatibility::Incompatible,
                ActionOptionEffectCompatibility::CompatibleIfChanged,
            )
        } else {
            ActionOptionEffectCompatibility::Incompatible
        }
    }
}

/// A systemd option value and its effect, altered from original
#[derive(Debug, Clone)]
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
        #[expect(clippy::unwrap_used, clippy::indexing_slicing)]
        let (cur_action, previous_actions) = actions[..=i].split_last().unwrap();
        match cur_eff.compatible(cur_action, previous_actions, updater, hardening_opts) {
            ActionOptionEffectCompatibility::Compatible => {}
            ActionOptionEffectCompatibility::CompatibleIfChanged(new_desc) => {
                log::debug!(
                    "Option effect {:?} is incompatible with {:?}, changing effect to {:?}",
                    cur_eff,
                    cur_action,
                    new_desc.effect
                );
                changed_desc = Some(new_desc);
            }
            ActionOptionEffectCompatibility::Incompatible => {
                log::debug!("Option effect {cur_eff:?} is incompatible with {cur_action:?}");
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
                OptionEffect::Cumulative(effects) => match &opt_value_desc.value {
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
                            ActionOptionEffectCompatibility::CompatibleIfChanged(opt_new_desc) => {
                                candidates.extend(opt_new_desc.new_options);
                                break;
                            }
                            ActionOptionEffectCompatibility::Incompatible => {}
                        }
                    }
                    _ => unreachable!(),
                },
            }
        }
    }

    // Merge paths in compatible options, post option merging
    for option in &mut candidates {
        if let OptionValue::List(ListOptionValue {
            values,
            mergeable_paths: true,
            ..
        }) = &mut option.value
        {
            // Note: this can simplify paths to a point where that negates another option, for example:
            // TemporaryFileSystem=/dev:ro
            // BindReadOnlyPaths=/dev
            // but at this point we lost the logical link between the two
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
        systemd::{KernelVersion, SystemdVersion, build_options},
    };

    fn test_options_safe(names: &[&str]) -> (Vec<OptionDescription>, HardeningOptions) {
        let sd_version = SystemdVersion::new(254, 0);
        let kernel_version = KernelVersion::new(6, 4, 0);
        let hardening_opts = HardeningOptions {
            systemd_options: Some(names.iter().map(|n| (*n).to_owned()).collect()),
            ..HardeningOptions::safe()
        };
        (
            build_options(&sd_version, &kernel_version, &hardening_opts),
            hardening_opts,
        )
    }

    fn test_options_strict(names: &[&str]) -> (Vec<OptionDescription>, HardeningOptions) {
        let sd_version = SystemdVersion::new(254, 0);
        let kernel_version = KernelVersion::new(6, 4, 0);
        let hardening_opts = HardeningOptions {
            systemd_options: Some(names.iter().map(|n| (*n).to_owned()).collect()),
            ..HardeningOptions::strict()
        };
        (
            build_options(&sd_version, &kernel_version, &hardening_opts),
            hardening_opts,
        )
    }

    #[test]
    fn test_resolve_protect_system() {
        let _ = simple_logger::SimpleLogger::new().init();

        let (opts, hardening_opts) = test_options_safe(&["ProtectSystem"]);

        let actions = vec![];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].to_string(), "ProtectSystem=strict");

        let actions = vec![ProgramAction::Write("/sys/whatever".into())];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].to_string(), "ProtectSystem=strict");

        let actions = vec![ProgramAction::Write("/var/cache/whatever".into())];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].to_string(), "ProtectSystem=full");

        let actions = vec![ProgramAction::Write("/etc/plop.conf".into())];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].to_string(), "ProtectSystem=true");

        let actions = vec![ProgramAction::Write("/usr/bin/false".into())];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 0);
    }

    #[test]
    fn test_resolve_protect_home() {
        let _ = simple_logger::SimpleLogger::new().init();

        let (opts, hardening_opts) = test_options_safe(&["ProtectHome"]);

        let actions = vec![];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].to_string(), "ProtectHome=true");

        let actions = vec![ProgramAction::Read("/home/user/data".into())];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 0);

        let actions = vec![ProgramAction::Write("/home/user/data".into())];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 0);

        let actions = vec![ProgramAction::Create("/home/user/data".into())];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 0);

        let actions = vec![
            ProgramAction::Create("/home/user/data".into()),
            ProgramAction::Read("/home/user/data".into()),
        ];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 0);

        let actions = vec![
            ProgramAction::Create("/home/user".into()),
            ProgramAction::Create("/home/user/data".into()),
            ProgramAction::Read("/home/user/data".into()),
        ];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].to_string(), "ProtectHome=tmpfs");

        let actions = vec![
            ProgramAction::Create("/home/user".into()),
            ProgramAction::Create("/home/user/data".into()),
            ProgramAction::Write("/home/user/data".into()),
        ];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].to_string(), "ProtectHome=tmpfs");

        let actions = vec![ProgramAction::Read("/home/data".into())];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 0);

        let actions = vec![ProgramAction::Write("/home/data".into())];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 0);

        let actions = vec![ProgramAction::Create("/home/data".into())];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].to_string(), "ProtectHome=tmpfs");

        let actions = vec![ProgramAction::Exec("/home/data".into())];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 0);

        let actions = vec![
            ProgramAction::Create("/home/data".into()),
            ProgramAction::Read("/home/data".into()),
        ];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].to_string(), "ProtectHome=tmpfs");

        let actions = vec![
            ProgramAction::Create("/home/data".into()),
            ProgramAction::Write("/home/data".into()),
        ];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].to_string(), "ProtectHome=tmpfs");

        let actions = vec![
            ProgramAction::Create("/home/data".into()),
            ProgramAction::Exec("/home/data".into()),
        ];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].to_string(), "ProtectHome=tmpfs");
    }

    #[test]
    fn test_resolve_private_tmp() {
        let _ = simple_logger::SimpleLogger::new().init();

        let (opts, hardening_opts) = test_options_safe(&["PrivateTmp"]);

        let actions = vec![];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].to_string(), "PrivateTmp=true");

        let actions = vec![ProgramAction::Read("/tmp/data".into())];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 0);

        let actions = vec![ProgramAction::Write("/tmp/data".into())];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 0);

        let actions = vec![ProgramAction::Create("/tmp/data".into())];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].to_string(), "PrivateTmp=true");

        let actions = vec![ProgramAction::Exec("/tmp/data".into())];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 0);

        let actions = vec![
            ProgramAction::Create("/tmp/data".into()),
            ProgramAction::Read("/tmp/data".into()),
        ];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].to_string(), "PrivateTmp=true");

        let actions = vec![
            ProgramAction::Create("/tmp/data".into()),
            ProgramAction::Write("/tmp/data".into()),
        ];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].to_string(), "PrivateTmp=true");

        let actions = vec![
            ProgramAction::Create("/tmp/data".into()),
            ProgramAction::Exec("/tmp/data".into()),
        ];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].to_string(), "PrivateTmp=true");
    }

    #[test]
    fn test_resolve_inaccessible_paths() {
        let _ = simple_logger::SimpleLogger::new().init();

        let (opts, hardening_opts) = test_options_strict(&["InaccessiblePaths"]);

        let actions = vec![];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].to_string(), "InaccessiblePaths=-/");

        let actions = vec![ProgramAction::Read("/".into())];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 1);
        assert!(candidates[0].to_string().starts_with("InaccessiblePaths="));
        let OptionValue::List(opt_list) = &candidates[0].value else {
            panic!();
        };
        assert!(opt_list.values.contains(&"/boot".to_owned()));
        assert!(opt_list.values.contains(&"/dev".to_owned()));
        assert!(opt_list.values.contains(&"/etc".to_owned()));
        assert!(opt_list.values.contains(&"/home".to_owned()));
        assert!(opt_list.values.contains(&"/root".to_owned()));
        assert!(opt_list.values.contains(&"/sys".to_owned()));
        assert!(opt_list.values.contains(&"/tmp".to_owned()));
        assert!(opt_list.values.contains(&"/usr".to_owned()));
        assert!(opt_list.values.contains(&"/var".to_owned()));
        assert!(!opt_list.values.contains(&"/proc".to_owned()));
        assert!(!opt_list.values.contains(&"/run".to_owned()));

        let actions = vec![ProgramAction::Read("/var/data".into())];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 3);
        assert_eq!(candidates[0].to_string(), "TemporaryFileSystem=/:ro");
        assert_eq!(candidates[1].to_string(), "BindReadOnlyPaths=-/var/data");
        assert_eq!(candidates[2].to_string(), "PrivateMounts=true");

        let actions = vec![
            ProgramAction::Exec("/usr/bin/prog".into()),
            ProgramAction::Read("/var/data".into()),
        ];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 3);
        assert_eq!(candidates[0].to_string(), "TemporaryFileSystem=/:ro");
        assert_eq!(
            candidates[1].to_string(),
            "BindReadOnlyPaths=-/usr/bin/prog -/var/data"
        );
        assert_eq!(candidates[2].to_string(), "PrivateMounts=true");

        let actions = vec![
            ProgramAction::Exec("/usr/bin/prog".into()),
            ProgramAction::Write("/var/data".into()),
        ];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 4);
        assert_eq!(candidates[0].to_string(), "TemporaryFileSystem=/:ro");
        assert_eq!(
            candidates[1].to_string(),
            "BindReadOnlyPaths=-/usr/bin/prog"
        );
        assert_eq!(candidates[2].to_string(), "BindPaths=-/var/data");
        assert_eq!(candidates[3].to_string(), "PrivateMounts=true");

        let actions = vec![
            ProgramAction::Exec("/usr/bin/prog".into()),
            ProgramAction::Create("/var/data".into()),
            ProgramAction::Write("/var/data".into()),
        ];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 4);
        assert_eq!(candidates[0].to_string(), "TemporaryFileSystem=/:ro");
        assert_eq!(
            candidates[1].to_string(),
            "BindReadOnlyPaths=-/usr/bin/prog"
        );
        assert_eq!(candidates[2].to_string(), "BindPaths=-/var");
        assert_eq!(candidates[3].to_string(), "PrivateMounts=true");

        let actions = vec![
            ProgramAction::Exec("/usr/bin/prog".into()),
            ProgramAction::Create("/var/dir/data".into()),
            ProgramAction::Write("/var/dir/data".into()),
        ];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 4);
        assert_eq!(candidates[0].to_string(), "TemporaryFileSystem=/:ro");
        assert_eq!(
            candidates[1].to_string(),
            "BindReadOnlyPaths=-/usr/bin/prog"
        );
        assert_eq!(candidates[2].to_string(), "BindPaths=-/var/dir");
        assert_eq!(candidates[3].to_string(), "PrivateMounts=true");

        let actions = vec![
            ProgramAction::Exec("/usr/bin/prog".into()),
            ProgramAction::Read("/var/data".into()),
            ProgramAction::Write("/var/data".into()),
        ];
        let candidates = resolve(&opts, &actions, &hardening_opts);
        assert_eq!(candidates.len(), 4);
        assert_eq!(candidates[0].to_string(), "TemporaryFileSystem=/:ro");
        assert_eq!(
            candidates[1].to_string(),
            "BindReadOnlyPaths=-/usr/bin/prog"
        );
        assert_eq!(candidates[2].to_string(), "BindPaths=-/var/data");
        assert_eq!(candidates[3].to_string(), "PrivateMounts=true");
    }
}
