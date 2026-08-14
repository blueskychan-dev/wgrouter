# HUMAX Design Language — Extracted

Source: `HUMAX.htm` (1678 lines), a browser "Save Page As" capture of the Home
screen of a **HUMAX T3ATv2** router admin panel, firmware 1.0.44, build
2019-04-01, captured in Extender mode at `192.168.1.148`.

That capture is HUMAX's own firmware markup, so it is kept locally and is not
redistributed in this repository — the line citations below refer to it, and
this document plus `web/static/css/tokens.css` are the extracted result.

**This document reports only what that file proves.** Nothing here is invented.
Every token carries a basis tag and line citations so you can check any claim.

---

## 0. Provenance and confidence

### 0.1 What we have and what we do not

The capture saved the HTML but **not** its sibling `HUMAX_files/` directory. That
directory is absent from this machine entirely (searched: repo, `$HOME`, `/tmp`,
browser caches, archives). Missing therefore:

| Missing | Referenced at | What it held |
|---|---|---|
| `style_TGJF.css` | line 11 | **The entire stylesheet.** The only one for the whole panel. |
| 11 JS files | lines 12–23 | `jcommon`, `language_en`, `jquery.min`, `json2.min`, `callHeader`, `callMenu`, `callFooter`, `callPopup`, `language`, `b28n`, `util_gw` |
| 33 distinct PNGs | throughout | logo, 8 nav icons, LED artwork, 20 network-map state icons, control icons |
| `favicon.ico` | line 10 | — |

**Consequence, stated plainly:** structure, geometry and behaviour are recoverable
in high detail. **Surface appearance is substantially not.** Font family,
letter-spacing, line-height, border radii, shadows, gradients, hover/focus
treatments, button appearance and — importantly for us — **all success/warning/
error state colors** exist only in the missing CSS and PNGs. See §11.

Per the brief's instruction not to invent a design: those tokens are recorded as
UNKNOWN below and quarantined in `tokens.css`. They are **not** guessed.

### 0.2 Basis legend

Every token below is tagged:

- **`literal`** — the value appears verbatim in the file (e.g. `bgcolor="#1e9bf0"`).
- **`inferred`** — decoded from the self-documenting class-name convention. The
  panel names classes after their values: `f12` → `font-size:12px`, `c464646` →
  `color:#464646`, `col-l-260` → a 260px left column, `pl-10` → `padding-left:10px`,
  `h33` → `height:33px`. The decoding is systematic and internally consistent
  across all 13 such classes, but **no declaration exists in the file to confirm it.**
- **`structural`** — derived from DOM shape rather than a stated value.
- **`UNKNOWN`** — lives only in the missing CSS/JS/PNGs. Not guessed.

### 0.3 Method

Five independent extraction passes (layout/nav, type/color, components, spacing,
assets/behaviour), each adversarially verified against the file by a separate
reviewer instructed to reject anything unsupported, then a completeness critique.
The verification rejected one finding outright and issued 40+ corrections;
all counts below are the post-verification, mechanically re-checked values.

---

## 1. Layout skeleton

Fixed-width, centered, table-based. **There is no responsive dimension to this
design**: no `<meta name="viewport">` (verified: zero occurrences), fixed pixel
widths throughout, and the only percentage widths outside `width="100%"` are the
device-list columns.

```
<body>                                                        line 961
└── div#container                                             962 … 1660
    ├── div#languageDiv         ← language dropdown overlay   966
    └── table[align=center; border-spacing:0]                 969   ← 3 rows, 2 cols
        │
        ├── tr > td#headerDiv[colspan=2, bgcolor=#1e9bf0]     971–977
        │       └── div.header                                975
        │           ├── div.pro-logo      → logo img + td.pro-model "T3ATv2"
        │           ├── div.pro-led-box   → 6 port LEDs + td.pro-lang
        │           ├── (spacer td height=14)
        │           └── div.pro-btn-box   → div.domaname > ul  (Easy Setup • Logout • Help)
        │
        ├── tr > td.main-td[no colspan]                       980–981
        │       └── table[width=982, height=600, align=center] 983   ← the body grid
        │           └── tr
        │               ├── td#menuDiv[width=260px, bgcolor=#f1f2f3, valign=top]  986–1074
        │               │       └── 10px spacer + 8 nav anchors
        │               └── td#contentDiv[width:100%; margin 15px 40px]           1078
        │                       └── table[width=750]          1081  ← content measure
        │                           ├── title block (f16 title / 5px / f10 description / 30px)
        │                           ├── network map table.table[height=142]
        │                           └── 10 × panel div > table.table
        │
        └── tr > td[height=60, colspan=2, bgcolor=#5b5d5f]    1657
                └── div.footer > div.copyright + div.customer
```

**Width arithmetic does not close, and this matters.** The body grid declares
`width="982"` (line 983), but its two cells declare `260px` (986) + a 750px inner
table (1081) = **1010px minimum before the content cell's 40px side margins**.
HTML `width` is a *preferred*, not maximum, width, so the table renders wider than
982. The true rendered width is **not derivable from this file** — see §11 row 15.
The one real measurement in the file, the dropdown's runtime `left:1249.1666…px`
(966), proves only that the capture viewport was ≳1389px wide.

Also note: `td#contentDiv` declares `margin-left/right:40px; margin-top/bottom:15px`
and `float:left` (1078). **Margins on a table-cell box are ignored in table layout**,
and `float` does not apply to a `<td>` unless the missing CSS changes its `display`.
The declaration is literal; its rendered effect is unverifiable.

### Structural facts

- **31 live `<table>` elements**, maximum nesting depth **5**. Three stacked
  single-cell wrapper tables (1081 → 1084 → 1087) exist purely as structural padding.
- Exactly two grid widths in the whole document: `colspan="2"` ×33 (the key/value
  panel) and `colspan="5"` ×1 (the device list). **Zero `rowspan`** — strictly
  rectangular, no cell merging.
- **28 of 31 tables carry `cellpadding="0" cellspacing="0"`**; the two shell
  tables use `style="border-spacing:0px"`. Implication: **no implicit spacing
  exists anywhere.** Every visible gap is an explicit spacer element. This is the
  single most important structural idiom to reproduce.

---

## 2. Navigation — **a left sidebar, definitively**

You asked me to settle this from the file. It is **not tabs**. It is a **fixed
260px left sidebar** occupying its own table cell for the full height of the body
grid, with eight stacked icon+label rows.

`td#menuDiv[width="260px" bgcolor="#f1f2f3" valign="top"]` — lines 986–1074.
(`width="260px"` is non-conforming HTML, but browsers parse the leading digits and
apply `width:260px`; it is not inert.)

### One nav item, verbatim (lines 988–997)

```html
<a href="http://192.168.1.148/home.htm">
  <div id="1" class="menu-out-2" onmouseover="My_T_Over(1,1)" onmouseout="My_T_Out(1,1)">
    <ul style="clear:both;">
      <li style="float:left;height:36px;padding-left:8px;">
        <img id="img1" src="HUMAX_files/icon_Home_ON_TGJF.png" border="0">
      </li>
      <li><span id="home top">Home</span></li>
    </ul>
  </div>
</a>
```

The anchor wraps the entire row (block-in-inline — invalid under the page's own
doctype, but that is what it does). Row height **36px**, icon gutter
**`padding-left:8px`**, `clear:both` on the `<ul>`.

### The eight items, in order

| # | Label | href | State class | Visible |
|---|---|---|---|---|
| 1 | Home | `home.htm` | `menu-out-2` ← **active** | yes |
| 2 | Network | `tcpiplan.htm` | `menu-def-2` | yes |
| 3 | Wireless 2.4GHz | `formWlanRedirect?…wlan_id=1` | `menu-def-2` | yes |
| 4 | Wireless 5GHz | `formWlanRedirect?…wlan_id=0` | `menu-def-2` | yes |
| 5 | Media Share | `diskinfo.htm` | `menu-def-2` | **no** — build-time flag |
| 6 | QoS (Quality of Service) | `ip6_qos.htm` | `menu-def-1` | **no** — runtime |
| 7 | Security | `accessmanagement.htm` | `menu-def-2` | **no** — runtime |
| 8 | Management | `wlsch.htm` | `menu-def-2` | yes |

Item 6 is the sole `menu-def-1`; the reason is not recoverable (plausibly a
two-line-label variant, since it has by far the longest label — but that is a
guess, not a finding).

### How state is applied — and why

Nav divs carry **bare ordinal ids `1`–`8`**, icons carry `img1`–`img8`, and every
one of the 16 hover handlers passes the matching ordinal: `My_T_Over(N,1)` /
`My_T_Out(N,1)`. The active item's icon filename carries an uppercase `_ON`
suffix (`icon_Home_ON_TGJF.png`) where the seven inactive icons do not.

**Ids beginning with a digit are not addressable by CSS or `querySelector`.** That
is almost certainly *why* state is swapped imperatively in JS (class + `img.src`)
rather than by a CSS selector — the markup makes the CSS route impossible. Nine
further ids contain spaces (`"home top"` … `"management top"`, `"title info"`),
which are likewise unaddressable.

**For wgrouter: do not reproduce this.** Use valid ids and drive active state with
a server-rendered class. The *visual* convention to preserve is: distinct resting
class for the active item, and a distinct icon for it.

The second argument to `My_T_Over(N,1)` is always `1`; its meaning is UNKNOWN
(lives in the missing `callMenu_TGJF.js`).

---

## 3. Color

### 3.1 Literal colors — four, all of them

| Token | Hex | Where | Line | Basis |
|---|---|---|---|---|
| Header band / brand primary | `#1e9bf0` | `td#headerDiv` `bgcolor`, repeated on inner `div.header` | 972, 975 | literal |
| Sidebar surface | `#f1f2f3` | `td#menuDiv` `bgcolor` | 986 | literal |
| Footer band | `#5b5d5f` | footer `td` `bgcolor` | 1657 | literal |
| Hairline / divider | `#dcdcdc` | `border:1px solid #dcdcdc; background-color:#dcdcdc` on 3 empty connector cells | 1156, 1169, 1190 | literal |

That is the complete set. **Page background, content background, panel background,
table-header background and row-rule colors are all absent** — they are CSS.

### 3.2 Inferred colors — the `c*` utility family (exactly four)

| Class | Hex | Applied to | Lines | Basis |
|---|---|---|---|---|
| `c464646` | `#464646` | page title, page description, empty-state headline + body | 1090, 1100, 1591, 1593 | inferred |
| `c141414` | `#141414` | map node captions (static), never on an anchor | 1203, 1204, 1211, 1221 (+ JS 613, 870, 923, 934) | inferred |
| `c0a87e6` | `#0a87e6` | **the only color class ever applied to an `<a>`** — link and active-node caption | 1199, 1200, 1644 (+ JS 263, 271) | inferred |
| `c1e1e1e` | `#1e1e1e` | one list section label | 1635 | inferred |

Semantic read: `#464646` is the content grey, `#141414` the darkest static text,
`#0a87e6` the **link/accent** blue (a slightly deeper sibling of the `#1e9bf0`
header blue), `#1e1e1e` a near-black heading used once.

**Crucially: the 46 label cells, 46 value cells, 10 section headers, 4 column
headers, 8 nav labels and every header/footer string carry *no* color class at
all.** Their colors are CSS-only. The four `c*` values above cover a small minority
of the page's text.

### 3.3 State colors — **NOT EXTRACTABLE**

This is the gap most likely to bite us, so it is worth being precise about.

- `class="on"` occurs **exactly once** in 1678 lines (line 1234, `span#wanstatus`)
  and carries no color evidence whatsoever.
- `class="off"` occurs 22 times, serving **two unrelated purposes** (§7.1).
- All real status signalling was done with **PNG artwork**, not color:
  `icon_map_internet_connect` / `_on_x` / `_off_v` / `_disconnect`,
  `icon_map_router_off_1/2/3`, `icon_status_on`.
- **There is no error or warning UI anywhere in this file.** Failures go to a
  native `alert()` (953) and `console.log` (141–143). Not merely unstyled — the
  pattern is absent.

So HUMAX's success/warn/error palette cannot be recovered from this capture, and
wgrouter needs online/idle/never-connected indicators. **This needs your decision —
see §12.**

---

## 4. Typography

### 4.1 The type scale — five steps, exhaustive

Nine live usages of five classes. (Verified: no `f11`, `f14`, `f15`, `f17`, `f20`
etc. exist. A tenth usage at line 1215 is inside a JS comment — dead.)

| Class | Size | Role in the design | Lines | Basis |
|---|---|---|---|---|
| `f18` | 18px | Empty-state headline — largest type on the page | 1591 | inferred |
| `f16` | 16px | **Page title** — the only in-flow heading; pairs with `bold` | 1090 | inferred |
| `f13` | 13px | Empty-state body copy | 1593 | inferred |
| `f12` | 12px | Map node captions — the most repeated size | 1199, 1203, 1211, 1221 | inferred |
| `f10` | 10px | Page description under the title; list section label | 1100, 1635 | inferred |

Note the striking omission: **every high-frequency text style in the panel
(`col-l-260`, `col-r`, `col-tbl-th`, `col-list-th`, nav labels, header, footer)
carries no size class.** The base body size is CSS-only and therefore UNKNOWN.
The `f*` classes are exceptions applied to a handful of special cells, not the
type system itself.

### 4.2 Weight

Total evidence in the entire file:

- `class="bold"` — once, on the page title (1090), alongside `f16 c464646`.
- `<b>` — **five live elements**: the empty-state headline (1591) and the four
  device-list column headers (1637, 1639, 1640, 1641). A sixth is inside an HTML
  comment (1638).

Everything else is UNKNOWN.

### 4.3 Family, letter-spacing, line-height — **NOT EXTRACTABLE**

Zero occurrences of `font`, `letter-spacing` or `line-height` in 1678 lines.

**One hard, file-sourced constraint survives:** the language dropdown contains the
literal UTF-8 string `ภาษาไทย` (line 966). **Whatever the stack was, it rendered
Thai and Latin.** That constrains both family choice and leading (Thai needs more
line-height than Latin).

**And line-height is load-bearing here**, which is easy to miss: the eight
inter-panel gaps in the content column are bare `<br>` elements (1270, 1297, 1324,
1366, 1410, 1469, 1528, 1582). The most visible vertical rhythm in the whole
content area *is* one line-height — an unknown value.

---

## 5. Spacing scale — measured, not invented

Because 28 of 31 tables zero out implicit spacing, every gap is hand-authored and
countable. This is the one token category the file documents *unusually well*.

### 5.1 Vertical spacers (empty `<td height="N">`)

| Step | Count | Purpose | Load-bearing? |
|---|---|---|---|
| **9px** | 19 | **The panel inset.** Opens all 10 panels; closes 8 of them. | **yes — the dominant step** |
| 30px | 1 | Title block → first panel | yes |
| 20px | 2 | Empty-state top and bottom | — |
| 15px | — | `contentDiv` top/bottom margin (1078) | declared; effect unverifiable |
| 14px | 1 | Header LED row → button bar (975) | yes |
| 11px | 2 | USB/Printer panel bottom inset — **the one inconsistency**: these two panels close with 11px where the other eight close with 9px | — |
| 10px | 1 | Sidebar top spacer (987) | yes |
| 5px | 1 | Page title → page description | yes |
| 44px | 3 | Map connector vertical offset (= the 88px icon row ÷ 2) | yes |
| 3px | 2 | Language dropdown top/bottom pad (966) | yes |

Also: `h33` → 33px, the list section-label row height (1635, inferred).

### 5.2 Horizontal spacers

| Step | Source | Basis |
|---|---|---|
| 40px | `contentDiv` left/right margin (1078) — largest horizontal value | literal (effect unverifiable) |
| 14px | footer separator image padding: `padding: 0 0 0 14px` (1657) | literal |
| 10px | `pl-10` on the four password-toggle icons | inferred |
| 8px | nav icon gutter `padding-left:8px` (×8); `pr-8` on 3 `col-r` cells | literal / inferred |
| 1px | the connector hairline border | literal |

### 5.3 The resulting scale

**`3 · 5 · 8 · 9 · 10 · 11 · 14 · 15 · 20 · 30 · 40 · 44`**

Not a geometric or 4/8pt scale — a hand-tuned set with **9px as the workhorse**.
Reproduce it as-is; do not "regularise" it to a modern 8pt grid.

### 5.4 Content dimensions (distinct from spacing)

| Value | What |
|---|---|
| 982 × 600 | authored body grid (983) — see §1 on why it does not close |
| 750 | content measure (1081) |
| 260 | sidebar width (986) **and** the key/value label column (`col-l-260`) |
| 140 | map connector columns (×6); language dropdown table (966) |
| 88 / 24 / 142 | map icon row / caption row / table total (1109–1198) |
| 60 | footer band height (1657) |
| 36 | nav row height |
| 530 | footer link cell (1657) |
| 7% / 26% / 26% / 24% | device-list columns — sum to 83%, with a commented-out 17% "Interface" column (1638) accounting for the remainder |

---

## 6. Borders, radii, shadows

| Token | Value | Basis |
|---|---|---|
| Hairline | `1px solid #dcdcdc`, on 3 empty connector cells with matching `background-color` | literal (1156, 1169, 1190) |
| All table chrome | `border="0"` on every table | literal |
| Panel rules, row separators, header underlines | — | **UNKNOWN** (CSS-only) |
| Border radii | — | **UNKNOWN** — zero occurrences of `radius` |
| Shadows | — | **UNKNOWN** — zero occurrences |
| Gradients | — | **UNKNOWN** — zero occurrences. `bgcolor` proves only that a flat fallback existed |

The rendered thickness of the connector rule is **not** derivable: it is a `1px`
border on an *empty* cell, whose height depends on missing line-height/padding rules.

---

## 7. Component patterns

Each of these is a DOM recipe to reproduce.

### 7.1 Section panel — the primary content container (10 instances)

```html
<div id="div_lan" class="off" style="display: none;">
  <table width="100%" border="0" cellpadding="0" cellspacing="0" class="table">
    <tr><td colspan="2" class="col-tbl-th">LAN</td></tr>   <!-- section header -->
    <tr><td colspan="2" height="9"></td></tr>              <!-- 9px inset -->
    …key/value rows…
    <tr><td colspan="2" height="9"></td></tr>              <!-- 9px inset -->
  </table>
  <br>                                                      <!-- inter-panel gap -->
</div>
```

Ten identical instances (1228, 1275, 1301, 1328, 1372, 1415, 1474, 1533, 1601, 1621).
Three carry a `<span>` inside `col-tbl-th` so the **title can be retitled at
runtime** (`apmode_name`, `apcli_name`, `apcli_name5g`) — panel titles are live
text, never baked artwork. All visual chrome of `col-tbl-th` is UNKNOWN.

### 7.2 Key/value row — the workhorse (46 instances)

```html
<tr>
  <td class="col-l-260">IP Address</td>
  <td class="col-r"><span id="lanip">192.168.1.148</span></td>
</tr>
```

Exactly 46 `col-l-260` and 46 `col-r`. Modifiers: three `col-r` add `pr-8`
(1605, 1614, 1625); two `col-l-260` add `valign="top"` (1604, 1624). Eight `<tr>`
carry ids so whole rows can be shown/hidden. **Every value is a `<span>` with an
id** — the live-data seam. No `col-l-260` or `col-r` cell carries any typography
class; their padding, size, color and separators are all UNKNOWN.

An "empty label" variant exists for right-aligned actions: `<td class="col-l-260"></td>`
+ `<td class="col-r pr-8" align="right">` holding a button (1613–1614).

### 7.3 Data/list table (1 instance, lines 1633–1645)

```html
<table width="100%" border="0" style="table-layout:fixed;">
  <thead>
    <tr class="off"><td colspan="5" class="f10 c1e1e1e h33">Connected Devices List</td></tr>
    <tr align="center">
      <td class="col-list-th" width="7%"><b>No.</b></td>
      <td class="col-list-th" width="26%"><b>Device Name</b></td>
      <td class="col-list-th" width="26%"><b>MAC Address</b></td>
      <td class="col-list-th" width="24%"><b>IP Address</b></td>
    </tr>
  </thead>
  <tbody id="div_stalist">
    <tr><td align="center">1</td>…</tr>
  </tbody>
</table>
```

The **only** table that opts out of the zero-spacing idiom. Header cells are
`<td class="col-list-th">` with `<b>` — **`<th>` is never used anywhere in the
file**. Every body cell is `align="center"`. Rows are injected as an HTML string
into `tbody#div_stalist`. Zebra striping, hover and borders are UNKNOWN.

### 7.4 Button — one variant only

```html
<input type="button" class="btn-def" value="Remove" name="umount" id="umount" onclick="delUsbDevice()">
```

**`btn-def` is the only button class in the entire panel** (one live instance at
1614; a commented-out Refresh at 1595 uses the same class). There is no
primary/secondary/danger distinction *represented at all* — the destructive
Remove action looks identical to a benign Refresh. Size, color, radius and all
states are UNKNOWN.

Quirk worth knowing: it is emitted **twice** — once through a JS `dw()` string and
once as literal markup — because the capture serialized `document.write` output
alongside the script that produced it. Do not reproduce the duplication.

### 7.5 State classes `.on` / `.off` — two distinct jobs

This distinction matters and is easy to get wrong.

**Job A — default-hidden container.** 11 panel divs carry `class="off"`. But it is
neither necessary nor sufficient for hiding: `div_no_usbdivice` (1585) is hidden
*without* it, and `div_apcli5g` (1370) carries it while being `display:block`. The
one unopposed case is `<tr class="off">` (1635) — so `.off` must at minimum be able
to express "hidden" on a `<tr>`.

**Job B — LED/icon state.** Six header LEDs are `div.pro-led{,2,3}.off` wrapping an
`<img>` that is **always the same asset** (`icon_status_on_TGJF.png`). The entire
lit/unlit appearance is therefore carried by `.off` in CSS — and is UNKNOWN.

`.on` appears once (1234) on `span#wanstatus`, whose text is written by JS.

Full census of the 22 `off` tokens: 11 panel divs + 6 LEDs + 4 password-toggle
images + 1 `<tr>`.

### 7.6 Progress meter

```html
<div id="total_size_bar" class="bar-bg"><div id="free_size_bar" class="bar usb_bg2"></div></div>
```

Fill is set as a percentage from JS. **Note a real trap:** the track's pixel width
is *read back* as an arithmetic denominator — `parseInt($("#total_size_bar").css("width"))`
(lines 150, 200). A missing CSS value is functionally load-bearing, not merely
cosmetic. If we reproduce this pattern, compute percentages server-side instead.

### 7.7 Password reveal (4 instances)

Masked span + `hidden=""` real span + toggle `<img>` swapping between
`btn_pw_show.png` / `btn_pw_hide.png`, with `class="pl-10 hand off"` and
`align="absmiddle"`.

**Directly relevant to us:** this is HUMAX's own "reveal a secret" control, and
wgrouter shows a one-time private key. Same pattern, same affordance.

### 7.8 Empty state (1585–1597)

Vertical rhythm, exactly: `20px → icon → 30px → f18 bold headline → 9px → f13 body → 20px`,
centered, with `align="absmiddle"` on the icon.

> "The USB device is not detected." / "Connect the USB device and try again."

A headline stating the condition plus one line of remedy. **This is the model for
our "no peers yet" and "no forwards yet" screens.**

### 7.9 Inline link list (`.domaname`)

Used in both header and footer: `<ul>` of `<li>`, separated by literal `•`
characters and one `|`, each separator its own `<li>`. In the footer, separators
are instead `<img>` rules with `padding: 0 0 0 14px`.

### 7.10 Language dropdown (966)

`table#languageTbl[width=140]` with 3px pad rows and two `td.languageOption` rows,
each with `onmouseover="setLanguageStyle(this,1)"`. Positioned by a JS-computed
inline `left/top`.

**`position` appears nowhere in the file** (verified zero) and `#languageDiv` has no
`display` property either — uniquely among conditional elements, **even its
show/hide mechanism is invisible here.** Surface, border, shadow and hover are UNKNOWN.

### 7.11 Modals — the pattern exists, the appearance does not

No dialog DOM exists in this file. Confirmation uses native `confirm()` (941) and
errors use native `alert()` (953).

But it would be wrong to conclude the design has no modal: **`callPopup_TGJF.js` is
one of four named shell modules** (alongside `callHeader`, `callMenu`, `callFooter`,
line 18), and the three header actions are href-less anchors dispatched by
`rel="easysetup" | "logout" | "help"` (975). **A popup pattern demonstrably exists;
only its appearance is unrecoverable.**

---

## 8. Behavioural conventions worth keeping

- **Live data by polling, not push.** `MainHomeStatus.asp` every **3s** (72–147),
  `USBStatus.asp` every **6s** (186–231), `NbtStatus.asp` on demand (236). All are
  `GET → JSON`, each field written into an id-bearing `<span>`.
  *We replace this with one SSE stream — but the DOM seam is the same: id-bearing
  spans patched in place.*
- **Two-dialect endpoint naming:** reads are `<Name>Status.asp`; writes are
  `POST /boafrm/form<Verb><Noun>` (`formUsbUmount`, `formWlanRedirect`).
  `/boafrm/` is the Boa web-server CGI prefix.
- **Every content-pane string passes through `dw(TOKEN)`** with the English text
  emitted after it — 52 `MM_*`, 4 `MSG_*`, 2 `BT_*` tokens. The English strings in
  the file *are* the recovered `en` locale table. (The header and footer are the
  exception: zero `dw()` calls, a dozen hard-coded strings.)
- **Every navigation is an uncached full page load** — three cache-defeat metas
  (7–9), no client-side routing. A multi-page app.
- **Localization requires a full reload** — all `dw()` sites are parse-time
  `document.write`.
- **An empty boilerplate `<form name="Status">` sits on the read-only Home page**
  (1108). This is the settings-form shell every writable page carries.
- **Modes change the *meaning* of a column, not just visibility:** in Extender mode
  the device list's "Device Name" column renders role labels (`Master AP`,
  `Extended Device`) instead of hostnames (250–257), under the same header.

---

## 9. Asset inventory

33 distinct PNGs, **none present**. 44 `<img>` elements, **zero with `alt`**, and
**zero with `width`/`height`** — so even icon dimensions are unrecoverable.

| Group | Files |
|---|---|
| Brand | `logo.png` |
| Nav (8) | `icon_Home_ON`, `icon_Network`, `icon_Wireless`, `icon_USB_Storage`, `icon_QoS`, `icon_Firewall`, `icon_Management` |
| LED | `icon_status_on` (one artwork serves all six ports) |
| Map (20) | `icon_map_internet_{connect,disconnect,on_x,off_v}`, `icon_map_router_off_{1,2,3}`, `icon_map_dual*`, `icon_map_usb{,_on}`, `icon_map_device{,_on}`, `icon_map_print{,_on}` |
| Controls | `btn_pw_show`, `btn_pw_hide` |
| Decorative | `icon_copyright`, `icon_footer_line`, `icon_status_smart-loaming`, `icon_usb_not` |

Two path forms appear: the saved `HUMAX_files/…_TGJF.png` (the `_TGJF` infix is a
browser save artifact, not part of the original name) and the runtime `/style/….png`.
**The live server served assets from `/style/`.**

State convention: `_ON` (active nav), `_on` (selected map node), `_off_N` (router
radio combinations), `_x` / `_v` (internet reachability). The suffix meanings are
inferred from branch structure; **what the artwork actually depicts is unknown.**

---

## 10. Accessibility — a faithful rebuild must *not* be faithful here

All verified zero across 1678 lines: `<h1>`–`<h6>`, `<th>`, `<label>`, `<fieldset>`,
`<legend>`, `<caption>`, `role=`, `aria-*`, `tabindex`, `alt=`, `<noscript>`.

**Of 13 interactive controls, exactly one is keyboard-focusable** (the Remove
button). The eight nav anchors are focusable but bind state to `onmouseover` only,
with no `onfocus` — keyboard users get zero state feedback. There is no `:focus`
evidence anywhere, so no focus affordance can even be inferred.

**Recommendation:** reproduce the *visual* language faithfully; do not reproduce
the accessibility. Use real `<th>`, `<label>`, one `<h1>` per page, `alt` text, and
a visible focus ring. This is invisible to the HUMAX aesthetic and costs nothing.
Flagging it because "match the extracted design" could otherwise be read as
requiring us to copy these defects — I've assumed you don't want that.

---

## 11. Definitive unknowns

What the brief asks for, versus what this file can supply.

| Token category | Verdict | Why |
|---|---|---|
| Surface hex colors | **PARTIAL** | Only 4 literals exist. Page/content/panel/table-header backgrounds absent. |
| Text hex colors | **PARTIAL (inferred)** | 4 `c*` values decode cleanly, but cover a small minority of the page's text; the rest is CSS-only. |
| **State colors (success/warn/error)** | **NOT EXTRACTABLE** | `.on` appears once with no color evidence; all state lived in PNGs; no error/warning UI exists at all. |
| Font family | **NOT EXTRACTABLE** | Zero `font` occurrences. Only constraint: must render Thai + Latin. |
| Font sizes | **PARTIAL (inferred)** | 5 steps decoded; the base body size is CSS-only. |
| Font weights | **PARTIAL** | One `bold` class + 5 `<b>`. Nothing else. |
| Letter-spacing | **NOT EXTRACTABLE** | Zero evidence. |
| Line-height | **NOT EXTRACTABLE — and load-bearing** | The 8 inter-panel gaps *are* `<br>`, i.e. one line-height. |
| Border radii | **NOT EXTRACTABLE** | Zero `radius` occurrences. |
| Border widths | **PARTIAL** | Exactly one border declared, on 3 connector cells. |
| Shadows / gradients | **NOT EXTRACTABLE** | Zero occurrences. |
| Spacing scale | **PARTIAL — unusually complete** | Every authored gap is countable (§5). Intra-cell padding is CSS-only. |
| Layout skeleton | **FULLY EXTRACTABLE** | §1. |
| Page width arithmetic | **NOT EXTRACTABLE** | 982 declared vs 1010 required; margin efficacy unknown. |
| Nav structure | **FULLY EXTRACTABLE** | Left sidebar, 260px, 8 items. |
| Nav appearance/hover | **PARTIAL** | Class names and mechanism yes; appearance no. |
| Panel / key-value / list-table structure | **FULL structure, NO visuals** | §7.1–7.3. |
| Button | **NOT EXTRACTABLE** | Class name only; one variant exists in the whole panel. |
| **Form controls** | **NOT EXTRACTABLE — and NOT REPRESENTED** | **Zero inputs, selects, checkboxes, radios, labels, fieldsets in 1678 lines.** The sole `<input>` is a button. |
| Modals | **Existence confirmed, appearance unknown** | `callPopup` is a named shell module; no dialog DOM here. |
| Icons | **NOT EXTRACTABLE** | 33 PNGs, 0 present, 0 dimensions declared. Filenames and state→file mapping *are* recoverable. |
| Hover / focus / active | **NOT EXTRACTABLE** | Hover exists only as JS hooks whose bodies are missing. Zero `:focus` evidence. |
| Transitions / motion | **NOT EXTRACTABLE** | Zero occurrences. |
| Responsive behaviour | **FULLY EXTRACTABLE — the answer is "none"** | No viewport meta; fixed-px throughout. |

### The gap that matters most for wgrouter

**Form controls.** Every screen we need to build except Status is a form: Add
Device, Add/Edit Forward, login, password change, the setup wizard. HUMAX's Home
page contains **not one** text input, select, checkbox, radio or label — so the
field styling, label alignment, validation and error presentation of this design
system are not merely unstyled here, they are **unrepresented**. This cannot be
inferred from what we have.

---

## 12. To close the gaps

In priority order. Nothing here is unclosable.

1. **`style_TGJF.css`** — on the device at `/style/style.css` (the saved `<link href>`
   was rewritten, so the exact original path is not recoverable). **Closes ~80% of
   every UNKNOWN above**: font stack, all `f*`/`c*` real values, `.table`,
   `.col-tbl-th`, `.col-l-260`, `.col-r`, `.col-list-th`, `.btn-def`, `.bar-bg`,
   `.on`/`.off`, `.menu-*`, `.pro-*`, `.hand`, radii, shadows, hover states.
2. **A full-width screenshot of `home.htm` as rendered.** Cheapest to obtain, and
   independently verifies the typeface, the 982-vs-1010 width question, `.on`/`.off`
   appearance, panel chrome, and every `f*`/`c*` inference. *If only two things are
   available, take this and item 1.*
3. **The `/style/` PNG directory (33 files)** — closes the status palette and icon
   dimensions.
4. **The HTML of any one *writable* page** (`tcpiplan.htm` or `wlsch.htm`) — the
   **only** way to obtain the form-control vocabulary. Home has none of it.
5. `callPopup_TGJF.js` + a screenshot with Logout or Help clicked — the modal pattern.
6. `callMenu_TGJF.js` — nav hover/active mechanism and the unseen hover class.

If the router is still reachable at `192.168.1.148`, items 1–4 are a few saves from
a browser with DevTools open.

---

## 13. Applying this to wgrouter

The mapping from HUMAX patterns to our screens, so the intent is unambiguous:

| wgrouter screen | HUMAX pattern to reuse |
|---|---|
| Shell (all screens) | §1 skeleton: blue header band, 260px `#f1f2f3` sidebar, 750px content, 60px `#5b5d5f` footer |
| Nav | §2 sidebar: 8→6 items (Status, WireGuard, Port Forwarding, Logs, System), 36px rows, 8px icon gutter, `_ON` active icon |
| **Status** | §7.1 panels of §7.2 key/value rows — exactly the Home page's Internet/LAN/Information panels |
| **Devices list** | §7.3 data table: `col-list-th` + `<b>` headers, `align="center"` body cells, `tbody` id as the live seam |
| **Add Device result** | §7.7 password-reveal pattern for the one-time private key; §7.4 `btn-def` for Download |
| **Device detail** | §7.1 + §7.2, one panel per group (identity, transfer, AllowedIPs, forwards targeting this peer) |
| **Port forwarding list** | §7.3 data table + the kernel-state column as a `.on`/`.off` indicator |
| **Add/Edit forward** | **No HUMAX precedent — see §11.** Needs a decision. |
| **Empty states** | §7.8 verbatim rhythm: 20 / icon / 30 / f18 bold / 9 / f13 / 20 |
| **Live updates** | §8 seam: id-bearing `<span>`s patched in place — but one SSE stream, not three polls |

Two things we must **not** copy: the digit-leading and space-containing ids (§2),
and the accessibility posture (§10).

### 13.1 What "match the extracted design" means in practice

Decided while building Milestone 2, recorded here so it is not re-litigated:

**We reproduce the look, not the 2010-era technique.** HUMAX built its layout
from nested tables — 31 of them, five deep, with three stacked single-cell
wrappers acting as padding (§1). `web/static/css/humax.css` gets the same
result with flex: fixed-width centered shell, blue band, 260px sidebar, 750px
content column, the 9px panel inset, the empty-state rhythm. Real `<table>` is
still used for genuinely tabular data, which is what it is for.

The visual tokens, spacing scale, component recipes and class names
(`.col-tbl-th`, `.col-l-260`, `.col-r`, `.col-list-th`, `.btn-def`, `.menu-def-2`)
are carried over verbatim, so the mapping back to the source stays legible.

Where the source was silent we say so in the CSS at the point of use rather than
quietly inventing: the form-control block in `humax.css` carries a comment
recording that HUMAX had no form controls at all, and what the invented styling
was derived from (the 260px label column, the 9px inset, the 1px `#dcdcdc`
hairline, square corners).

---

## 14. Checkpoint

Per Milestone 1, this document and `web/static/css/tokens.css` are the deliverable.
`tokens.css` contains the extracted tokens as custom properties, with everything
unverifiable confined to a clearly-marked quarantine block at the bottom that is
meant to be deleted and replaced once the real stylesheet arrives.

Open questions for you are in the reply accompanying this document, not here.
