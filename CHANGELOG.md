# CHANGELOG

## [1.0.0] - V1 Cut

Este release marca la distribución 1.0.0 de Verify.

Se provee como un binario (binary distribution) para Linux musl y macOS, operando sin depender del entorno de Rust.

### Features
* Soporte nativo y concurrente para los hooks `pre-commit` y `pre-push`.
* Prevención de filtración de datos sensibles si el archivo `.env` es modificado (modified).