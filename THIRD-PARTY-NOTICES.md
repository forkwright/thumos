# Third-party notices

## GC9306 gamma table

The six GC9306 gamma-register payloads (`0xF0` through `0xF5`) in
`crates/thumos/src/display.rs` are maintained from
`openLuat/luatos-soc-rtt`,
[`components/lcd/luat_lcd_gc9306.c`](https://github.com/openLuat/luatos-soc-rtt/blob/8001c7cd33c96755f8b7c68250681f479e90ff32/components/lcd/luat_lcd_gc9306.c),
at commit `8001c7cd33c96755f8b7c68250681f479e90ff32`. That repository and source
file were introduced together under the
[Apache License 2.0](https://github.com/openLuat/luatos-soc-rtt/blob/8001c7cd33c96755f8b7c68250681f479e90ff32/LICENSE).
A copy of that license is included at
`THIRD-PARTY-LICENSES/Apache-2.0.txt`.

The values have been transcribed from C calls into Rust byte slices; their
order and values are unchanged. The proprietary Fibocom/RDA implementation
happens to carry the same table, but it is cited only as an independent
comparison and supplies no permission for this repository.
