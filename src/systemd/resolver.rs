//! Resolver code that finds options compatible with program actions

use crate::{
    summarize::{NetworkActivity, ProgramAction},
    systemd::options::{
        ListMode, OptionDescription, OptionEffect, OptionValue, OptionValueEffect, OptionWithValue,
    },
};

impl OptionValueEffect {
    fn compatible(&self, action: &ProgramAction, prev_actions: &[ProgramAction]) -> bool {
        match self {
            OptionValueEffect::DenyAction(denied) => match denied {
                ProgramAction::NetworkActivity(denied) => {
                    if let ProgramAction::NetworkActivity(NetworkActivity { af, proto, kind }) =
                        action
                    {
                        !denied.af.intersects(af)
                            || !denied.proto.intersects(proto)
                            || !denied.kind.intersects(kind)
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
            OptionValueEffect::Multiple(effects) => {
                effects.iter().all(|e| e.compatible(action, prev_actions))
            }
        }
    }
}

pub(crate) fn actions_compatible(eff: &OptionValueEffect, actions: &[ProgramAction]) -> bool {
    for i in 0..actions.len() {
        if !eff.compatible(&actions[i], &actions[..i]) {
            log::debug!(
                "Option effect {:?} is incompatible with {:?}",
                eff,
                actions[i]
            );
            return false;
        }
    }
    true
}

pub(crate) fn resolve(
    opts: &Vec<OptionDescription>,
    actions: &[ProgramAction],
) -> Vec<OptionWithValue> {
    let mut candidates = Vec::new();
    for opt in opts {
        // Options are in the less to most restrictive order,
        // so for non cumulative options, iterate from the end
        for opt_value_desc in opt.possible_values.iter().rev() {
            match &opt_value_desc.desc {
                OptionEffect::None => {
                    candidates.push(OptionWithValue {
                        name: opt.name.to_owned(),
                        value: opt_value_desc.value.clone(),
                    });
                    break;
                }
                OptionEffect::Simple(effect) => {
                    if actions_compatible(effect, actions) {
                        candidates.push(OptionWithValue {
                            name: opt.name.to_owned(),
                            value: opt_value_desc.value.clone(),
                        });
                        break;
                    }
                }
                OptionEffect::Cumulative(effects) => {
                    match &opt_value_desc.value {
                        OptionValue::List {
                            values,
                            value_if_empty,
                            negation_prefix,
                            repeat_option,
                            mode,
                        } => {
                            let mut compatible_opts = Vec::new();
                            debug_assert_eq!(values.len(), effects.len());
                            for (optv, opte) in values.iter().zip(effects) {
                                let compatible = actions_compatible(opte, actions);
                                let enable_opt = match mode {
                                    ListMode::WhiteList => !compatible,
                                    ListMode::BlackList => compatible,
                                };
                                if enable_opt {
                                    compatible_opts.push(optv.to_string());
                                }
                            }
                            if !compatible_opts.is_empty() || value_if_empty.is_some() {
                                candidates.push(OptionWithValue {
                                    name: opt.name.to_owned(),
                                    value: OptionValue::List {
                                        values: compatible_opts,
                                        value_if_empty: value_if_empty.clone(),
                                        negation_prefix: *negation_prefix,
                                        repeat_option: *repeat_option,
                                        mode: mode.clone(),
                                    },
                                });
                            }
                            break;
                        }
                        _ => unreachable!(),
                    };
                }
            }
        }
    }
    candidates
}

#[expect(clippy::shadow_unrelated)]
#[cfg(test)]
mod tests {
    use super::*;

    use crate::{
        cl::HardeningMode,
        systemd::{build_options, KernelVersion, SystemdVersion},
    };

    fn test_options(names: &[&str]) -> Vec<OptionDescription> {
        let sd_version = SystemdVersion::new(254, 0);
        let kernel_version = KernelVersion::new(6, 4, 0);
        build_options(&sd_version, &kernel_version, &HardeningMode::Safe)
            .into_iter()
            .filter(|o| names.contains(&o.name))
            .collect()
    }

    #[test]
    fn test_resolve_protect_system() {
        let _ = simple_logger::SimpleLogger::new().init();

        let opts = test_options(&["ProtectSystem"]);

        let actions = vec![];
        let candidates = resolve(&opts, &actions);
        assert_eq!(candidates.len(), 1);
        assert_eq!(format!("{}", candidates[0]), "ProtectSystem=strict");

        let actions = vec![ProgramAction::Write("/sys/whatever".into())];
        let candidates = resolve(&opts, &actions);
        assert_eq!(candidates.len(), 1);
        assert_eq!(format!("{}", candidates[0]), "ProtectSystem=strict");

        let actions = vec![ProgramAction::Write("/var/cache/whatever".into())];
        let candidates = resolve(&opts, &actions);
        assert_eq!(candidates.len(), 1);
        assert_eq!(format!("{}", candidates[0]), "ProtectSystem=full");

        let actions = vec![ProgramAction::Write("/etc/plop.conf".into())];
        let candidates = resolve(&opts, &actions);
        assert_eq!(candidates.len(), 1);
        assert_eq!(format!("{}", candidates[0]), "ProtectSystem=true");

        let actions = vec![ProgramAction::Write("/usr/bin/false".into())];
        let candidates = resolve(&opts, &actions);
        assert_eq!(candidates.len(), 0);
    }

    #[test]
    fn test_resolve_protect_home() {
        let _ = simple_logger::SimpleLogger::new().init();

        let opts = test_options(&["ProtectHome"]);

        let actions = vec![];
        let candidates = resolve(&opts, &actions);
        assert_eq!(candidates.len(), 1);
        assert_eq!(format!("{}", candidates[0]), "ProtectHome=tmpfs");

        let actions = vec![ProgramAction::Write("/home/user/data".into())];
        let candidates = resolve(&opts, &actions);
        assert_eq!(candidates.len(), 1);
        assert_eq!(format!("{}", candidates[0]), "ProtectHome=true");

        let actions = vec![ProgramAction::Read("/home/user/data".into())];
        let candidates = resolve(&opts, &actions);
        assert_eq!(candidates.len(), 1);
        assert_eq!(format!("{}", candidates[0]), "ProtectHome=read-only");

        let actions = vec![
            ProgramAction::Create("/home/user/data".into()),
            ProgramAction::Read("/home/user/data".into()),
        ];
        let candidates = resolve(&opts, &actions);
        assert_eq!(candidates.len(), 1);
        assert_eq!(format!("{}", candidates[0]), "ProtectHome=true");
    }

    #[test]
    fn test_resolve_private_tmp() {
        let _ = simple_logger::SimpleLogger::new().init();

        let opts = test_options(&["PrivateTmp"]);

        let actions = vec![];
        let candidates = resolve(&opts, &actions);
        assert_eq!(candidates.len(), 1);
        assert_eq!(format!("{}", candidates[0]), "PrivateTmp=true");

        let actions = vec![ProgramAction::Write("/tmp/data".into())];
        let candidates = resolve(&opts, &actions);
        assert_eq!(candidates.len(), 1);
        assert_eq!(format!("{}", candidates[0]), "PrivateTmp=true");

        let actions = vec![ProgramAction::Read("/tmp/data".into())];
        let candidates = resolve(&opts, &actions);
        assert_eq!(candidates.len(), 0);

        let actions = vec![
            ProgramAction::Create("/tmp/data".into()),
            ProgramAction::Read("/tmp/data".into()),
        ];
        let candidates = resolve(&opts, &actions);
        assert_eq!(candidates.len(), 1);
        assert_eq!(format!("{}", candidates[0]), "PrivateTmp=true");
    }
}
