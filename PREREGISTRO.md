# Prerregistro de la medición / Measurement pre-registration

Escrito y commiteado antes de correr `txtoken-bench` por primera vez.
Written and committed before the first run of `txtoken-bench`.

Comando / command: `cargo run --release --bin txtoken-bench -- --tx 5000 --tamper-n 1000 --seed 42`

| Id | Métrica / metric | Esperado / expected | Criterio / pass if |
|---|---|---|---|
| M1 | Tamaño del Txn-Token en bytes (compacto) con el `tctx` y `rctx` del ejemplo de la Figura 4 del draft; y del access token de entrada | < 1 KiB | se reporta el número |
| M2 | Latencia de emisión (token exchange completo, incluye validar el access token) p50/p99 | decenas de µs | se reporta |
| M3 | Latencia por salto de la validación de la Sección 12.2, p50/p99, 5 saltos × 5000 transacciones; línea base: salto que sólo extrae y reenvía el header | p50 < 100 µs | se reporta, y el costo agregado = verify − forward |
| M4 | Fetches de JWKS durante la cadena después del warm-up | 0 | exactamente 0 |
| M5 | Rechazo de tokens alterados: 9 modos × 1000 transacciones, salto malicioso al azar en 0..3 | 100 % rechazado en el salto siguiente | 9000/9000 |
| C+ | Control positivo: cadena sin alterar | 100 % aceptado en los 5 saltos | 5000/5000 |
| C− | Control negativo: mismo experimento M5 con un verificador que no chequea firma | debe dejar pasar los 7 modos que sólo atacan la firma | 7 modos aceptados ≥ 99 % |

Límites conocidos antes de medir / known limits before measuring:
- Cadena en un solo proceso; no hay red ni TLS entre saltos. M3 es el costo de la validación, no latencia de red.
- Una sola máquina compartida, sin aislar CPU; los percentiles pueden variar entre corridas.
