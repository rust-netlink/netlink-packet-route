// SPDX-License-Identifier: MIT

buffer!(FreeBSDBuffer(4)    {
    length: (u16, 0..2),
    value_type: (u16, 2..4),
    value: (slice, 4..)
});
