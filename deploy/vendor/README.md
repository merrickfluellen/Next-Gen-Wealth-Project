# Self-hosted third-party libraries

These files are served same-origin so no third-party script host is trusted at runtime
(the CSP in `../netlify.toml` has no CDN in `script-src`). Each file is an unmodified copy
from the package's npm registry tarball. Every tarball was checked against the registry's
`dist.integrity` (sha512) before the files were copied. Each package's LICENSE sits next to its files.

Paths contain the exact version, so they are served with `Cache-Control: immutable`.
**To upgrade, add a new versioned folder; never change files in place.** Then update the
`<script>`/`<link>` tags in `../app.html`, this table, and `package.json`.

CI (`.github/workflows/ci.yml`) recomputes the sha384 of every file listed in the table below
and fails on a mismatch, or if a file under `deploy/vendor/` is missing from the table.

To re-verify by hand: `openssl dgst -sha384 -binary <file> | openssl base64 -A`.
The same values work as SRI `integrity` attributes.

| File | Source (npm tarball path) | Bytes | sha384 |
|---|---|---|---|
| `react@18.3.1/react.production.min.js` | `react@18.3.1 package/umd/react.production.min.js` | 10751 | `sha384-DGyLxAyjq0f9SPpVevD6IgztCFlnMF6oW/XQGmfe+IsZ8TqEiDrcHkMLKI6fiB/Z` |
| `react@18.3.1/LICENSE` | `react@18.3.1 package/LICENSE` | 1086 | `sha384-dIN5gxuW3odCH42AKpxql36fRQlrVsjCi4EJgGC2Ty8Ihkcq9cdrChEZpKhSAfks` |
| `react-dom@18.3.1/react-dom.production.min.js` | `react-dom@18.3.1 package/umd/react-dom.production.min.js` | 131835 | `sha384-gTGxhz21lVGYNMcdJOyq01Edg0jhn/c22nsx0kyqP0TxaV5WVdsSH1fSDUf5YJj1` |
| `react-dom@18.3.1/LICENSE` | `react-dom@18.3.1 package/LICENSE` | 1086 | `sha384-dIN5gxuW3odCH42AKpxql36fRQlrVsjCi4EJgGC2Ty8Ihkcq9cdrChEZpKhSAfks` |
| `leaflet@1.9.4/leaflet.js` | `leaflet@1.9.4 package/dist/leaflet.js` | 147552 | `sha384-cxOPjt7s7Iz04uaHJceBmS+qpjv2JkIHNVcuOrM+YHwZOmJGBXI00mdUXEq65HTH` |
| `leaflet@1.9.4/leaflet.css` | `leaflet@1.9.4 package/dist/leaflet.css` | 14806 | `sha384-sHL9NAb7lN7rfvG5lfHpm643Xkcjzp4jFvuavGOndn6pjVqS6ny56CAt3nsEVT4H` |
| `leaflet@1.9.4/images/layers-2x.png` | `leaflet@1.9.4 package/dist/images/layers-2x.png` | 1259 | `sha384-+F2ZWK/HTpkV9kN2HnMGCQOTM/cnQJLs770FLOeHznwVWRfDESI8z4JwcGYmy2Au` |
| `leaflet@1.9.4/images/layers.png` | `leaflet@1.9.4 package/dist/images/layers.png` | 696 | `sha384-80x85ZS+G189o0xL8E8D7BnfhuNss6EwUPHzG7e+qByRD2xnpxikZ6UQU4Re5nNy` |
| `leaflet@1.9.4/images/marker-icon-2x.png` | `leaflet@1.9.4 package/dist/images/marker-icon-2x.png` | 2464 | `sha384-bDEa1RhAAKIr/VQnMZ7gUhhXwmKYB4V0g8AsxOvCEPwGxfHCUEzAEMAEEzkjuxiA` |
| `leaflet@1.9.4/images/marker-icon.png` | `leaflet@1.9.4 package/dist/images/marker-icon.png` | 1466 | `sha384-wg83fCOXjBtqzFAWhTL9Sd9vmLUNhfEEzfmNUX9zwv2igKlz/YQbdapF4ObdxF+R` |
| `leaflet@1.9.4/images/marker-shadow.png` | `leaflet@1.9.4 package/dist/images/marker-shadow.png` | 618 | `sha384-dB8ivfvPGb1MSIzX8oWTakCxmq+VwqP/QL1TX4jT4INR3pM5T4FgF3Gx4mN3NTMq` |
| `leaflet@1.9.4/LICENSE` | `leaflet@1.9.4 package/LICENSE` | 1395 | `sha384-CXYK4I2izUBQWizu8sKhYyBLtabBOMnWJhiEcYE2hnY+ov3P+/NGnAkucH4hN0hK` |
| `three@0.149.0/three.min.js` | `three@0.149.0 package/build/three.min.js` | 608081 | `sha384-RRHfJ6w1mTlKUBMYT/hvnRiOzEB/vyRV3DrQOseb6oYfvaZSfdd0byS4bHps0k2R` |
| `three@0.149.0/LICENSE` | `three@0.149.0 package/LICENSE` | 1081 | `sha384-mUeSINM7srxm4QxsF/D79MqN53C5HNrAHfMITQbcYB4ik6l1vyy16IQ8CvUVdIDK` |

Tarballs: `https://registry.npmjs.org/<name>/-/<name>-<version>.tgz`.

Licenses: React and ReactDOM (MIT, Facebook, Inc. and its affiliates), Leaflet (BSD-2-Clause, Volodymyr Agafonkin / CloudMade),
three.js (MIT, three.js authors).

Note: `leaflet.js` ends with `//# sourceMappingURL=leaflet.js.map`. The map is not vendored, so
browser devtools log a harmless 404 for it when open. Normal page loads never request it.
