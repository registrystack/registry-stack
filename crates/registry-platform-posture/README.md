# Registry Platform Posture

`registry-platform-posture` holds the declared posture of a process, `development` or `production`, and the rules for reading it. It depends on nothing outside `std`, so any platform crate can name the type.

- `Posture`, `PostureSource` and `DeclaredPosture`. The accepted values are exactly `development` and `production`, case-sensitive, with no trimming. Neither the `--posture` flag nor the `REGISTRY_STACK_POSTURE` variable present means `production` with source `default`.
- `declared_from(flag, environment)` is pure and decides from the two inputs. A flag and a variable that are both present and equal give source `flag`. Different values are refused.
- `declared(flag)` reads the variable once. Call it only from `main` or a command dispatcher, and pass the result down as a value.
- `PostureError` has three cases with stable codes (`platform.posture.invalid-value`, `platform.posture.conflict`), value-free messages and a suggested action. The refusals happen before any file is read.
