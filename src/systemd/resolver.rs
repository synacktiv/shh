//! Resolver code that finds options compatible with program actions

use crate::summarize::ProgramAction;
use crate::systemd::options::{
    OptionDescription, OptionEffect, OptionValue, OptionValueEffect, OptionWithValue,
    SYSCALL_CLASSES,
};

impl OptionValueEffect {
    fn compatible(&self, action: &ProgramAction, prev_actions: &[ProgramAction]) -> bool {
        match self {
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
            OptionValueEffect::DenySyscall { class } => {
                if let ProgramAction::Syscalls(syscalls) = action {
                    let denied = SYSCALL_CLASSES.get(class).unwrap();
                    denied.intersection(syscalls).next().is_none()
                } else {
                    true
                }
            }
            OptionValueEffect::DenySocketFamily(denied_af) => {
                if let ProgramAction::NetworkActivity { af } = action {
                    af != denied_af
                } else {
                    true
                }
            }
            OptionValueEffect::DenyWxMemoryMapping => {
                !matches!(action, ProgramAction::WxMemoryMapping)
            }
            OptionValueEffect::Multiple(effects) => {
                effects.iter().all(|e| e.compatible(action, prev_actions))
            }
        }
    }
}

pub fn actions_compatible(eff: &OptionValueEffect, actions: &[ProgramAction]) -> bool {
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

pub fn resolve(
    opts: &Vec<OptionDescription>,
    actions: &[ProgramAction],
) -> anyhow::Result<Vec<OptionWithValue>> {
    let mut candidates = Vec::new();
    for opt in opts {
        // Options are in the less to most restrictive order,
        // so for non cumulative options, iterate from the end
        for opt_value_desc in opt.possible_values.iter().rev() {
            match &opt_value_desc.desc {
                OptionEffect::Simple(effect) => {
                    if actions_compatible(effect, actions) {
                        candidates.push(OptionWithValue {
                            name: opt.name.clone(),
                            value: opt_value_desc.value.clone(),
                        });
                        break;
                    }
                }
                OptionEffect::Cumulative(effects) => {
                    match &opt_value_desc.value {
                        OptionValue::DenyList(deny_list) => {
                            let mut compatible_opts = Vec::new();
                            debug_assert_eq!(deny_list.len(), effects.len());
                            for (optv, opte) in deny_list.iter().zip(effects) {
                                if actions_compatible(opte, actions) {
                                    compatible_opts.push(optv.to_string());
                                }
                            }
                            if !compatible_opts.is_empty() {
                                candidates.push(OptionWithValue {
                                    name: opt.name.clone(),
                                    value: OptionValue::DenyList(compatible_opts),
                                });
                                break;
                            }
                        }
                        OptionValue::AllowList(allow_list) => {
                            let mut compatible_opts = Vec::new();
                            debug_assert_eq!(allow_list.len(), effects.len());
                            for (optv, opte) in allow_list.iter().zip(effects) {
                                if !actions_compatible(opte, actions) {
                                    compatible_opts.push(optv.to_string());
                                }
                            }
                            candidates.push(OptionWithValue {
                                name: opt.name.clone(),
                                value: OptionValue::AllowList(compatible_opts),
                            });
                            break;
                        }
                        _ => unreachable!(),
                    };
                }
            }
        }
    }
    Ok(candidates)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::cl::HardeningMode;
    use crate::systemd::{build_options, KernelVersion, SystemdVersion};

    fn test_options(names: &[&str]) -> Vec<OptionDescription> {
        let sd_version = SystemdVersion::new(254, 0);
        let kernel_version = KernelVersion::new(6, 4, 0);
        build_options(&sd_version, &kernel_version, &HardeningMode::Safe)
            .into_iter()
            .filter(|o| names.contains(&o.name.as_str()))
            .collect()
    }

    #[test]
    fn test_resolve_protect_system() {
        let _ = simple_logger::SimpleLogger::new().init();

        let opts = test_options(&["ProtectSystem"]);

        let actions = vec![];
        let candidates = resolve(&opts, &actions).unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(format!("{}", candidates[0]), "ProtectSystem=strict");

        let actions = vec![ProgramAction::Write("/sys/whatever".into())];
        let candidates = resolve(&opts, &actions).unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(format!("{}", candidates[0]), "ProtectSystem=strict");

        let actions = vec![ProgramAction::Write("/var/cache/whatever".into())];
        let candidates = resolve(&opts, &actions).unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(format!("{}", candidates[0]), "ProtectSystem=full");

        let actions = vec![ProgramAction::Write("/etc/plop.conf".into())];
        let candidates = resolve(&opts, &actions).unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(format!("{}", candidates[0]), "ProtectSystem=true");

        let actions = vec![ProgramAction::Write("/usr/bin/false".into())];
        let candidates = resolve(&opts, &actions).unwrap();
        assert_eq!(candidates.len(), 0);
    }

    #[test]
    fn test_resolve_protect_home() {
        let _ = simple_logger::SimpleLogger::new().init();

        let opts = test_options(&["ProtectHome"]);

        let actions = vec![];
        let candidates = resolve(&opts, &actions).unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(format!("{}", candidates[0]), "ProtectHome=tmpfs");

        let actions = vec![ProgramAction::Write("/home/user/data".into())];
        let candidates = resolve(&opts, &actions).unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(format!("{}", candidates[0]), "ProtectHome=true");

        let actions = vec![ProgramAction::Read("/home/user/data".into())];
        let candidates = resolve(&opts, &actions).unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(format!("{}", candidates[0]), "ProtectHome=read-only");

        let actions = vec![
            ProgramAction::Create("/home/user/data".into()),
            ProgramAction::Read("/home/user/data".into()),
        ];
        let candidates = resolve(&opts, &actions).unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(format!("{}", candidates[0]), "ProtectHome=true");
    }

    #[test]
    fn test_resolve_private_tmp() {
        let _ = simple_logger::SimpleLogger::new().init();

        let opts = test_options(&["PrivateTmp"]);

        let actions = vec![];
        let candidates = resolve(&opts, &actions).unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(format!("{}", candidates[0]), "PrivateTmp=true");

        let actions = vec![ProgramAction::Write("/tmp/data".into())];
        let candidates = resolve(&opts, &actions).unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(format!("{}", candidates[0]), "PrivateTmp=true");

        let actions = vec![ProgramAction::Read("/tmp/data".into())];
        let candidates = resolve(&opts, &actions).unwrap();
        assert_eq!(candidates.len(), 0);

        let actions = vec![
            ProgramAction::Create("/tmp/data".into()),
            ProgramAction::Read("/tmp/data".into()),
        ];
        let candidates = resolve(&opts, &actions).unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(format!("{}", candidates[0]), "PrivateTmp=true");
    }
}
