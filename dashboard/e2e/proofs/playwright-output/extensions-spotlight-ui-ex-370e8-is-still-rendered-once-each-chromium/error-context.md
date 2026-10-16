# Instructions

- Following Playwright test failed.
- Explain why, be concise, respect Playwright best practices.
- Provide a snippet of code with the fix, if possible.

# Test info

- Name: extensions-spotlight-ui.spec.ts >> extensions spotlight >> a sponsored row ordered ahead of the featured ones is still rendered once each
- Location: e2e/extensions-spotlight-ui.spec.ts:219:3

# Error details

```
Error: expect(locator).toHaveCount(expected) failed

Locator:  getByTestId('catalog-featured-row').filter({ hasText: 'Fourth Buyer' })
Expected: 1
Received: 0
Timeout:  5000ms

Call log:
  - Expect "toHaveCount" with timeout 5000ms
  - waiting for getByTestId('catalog-featured-row').filter({ hasText: 'Fourth Buyer' })
    14 × locator resolved to 0 elements
       - unexpected value "0"

```

# Page snapshot

```yaml
- generic [ref=e2]:
  - link "Skip to content" [ref=e3] [cursor=pointer]:
    - /url: "#main-content"
  - generic [ref=e4]: Extensions
  - generic [ref=e5]:
    - complementary [ref=e6]:
      - generic [ref=e7]:
        - link "HOL Guard Home" [ref=e8] [cursor=pointer]:
          - /url: /
          - img [ref=e9]
          - generic [ref=e10]: HOL Guard
        - button "Collapse sidebar" [ref=e11] [cursor=pointer]:
          - img [ref=e12]
      - generic [ref=e14]:
        - navigation "Guard dashboard" [ref=e15]:
          - generic [ref=e16]:
            - paragraph [ref=e17]: Guard
            - link "Home" [ref=e18] [cursor=pointer]:
              - /url: /
              - img [ref=e20]
              - generic [ref=e22]: Home
            - link "Inbox, no Guard actions waiting" [ref=e23] [cursor=pointer]:
              - /url: /inbox
              - img [ref=e25]
              - generic [ref=e27]: Inbox
            - link "Protect" [ref=e28] [cursor=pointer]:
              - /url: /protect
              - img [ref=e30]
              - generic [ref=e32]: Protect
            - link "Evidence" [ref=e33] [cursor=pointer]:
              - /url: /evidence
              - img [ref=e35]
              - generic [ref=e37]: Evidence
          - generic [ref=e38]:
            - paragraph [ref=e39]: Manage
            - link "Extensions" [ref=e40] [cursor=pointer]:
              - /url: /extensions
              - img [ref=e42]
              - generic [ref=e44]: Extensions
            - link "Rules & exceptions" [ref=e45] [cursor=pointer]:
              - /url: /policy
              - img [ref=e47]
              - generic [ref=e50]: Rules & exceptions
            - link "Supply chain" [ref=e51] [cursor=pointer]:
              - /url: /supply-chain
              - img [ref=e53]
              - generic [ref=e55]: Supply chain
            - link "Settings" [ref=e56] [cursor=pointer]:
              - /url: /settings
              - img [ref=e58]
              - generic [ref=e60]: Settings
          - generic [ref=e61]:
            - paragraph [ref=e62]: Support
            - link "About" [ref=e63] [cursor=pointer]:
              - /url: /about
              - img [ref=e65]
              - generic [ref=e67]: About
        - generic [ref=e68]:
          - paragraph [ref=e69]: Quick actions
          - link "Local dashboard" [ref=e70] [cursor=pointer]:
            - /url: /
            - img [ref=e71]
            - generic [ref=e73]: Local dashboard
          - button "Open Guard Cloud" [ref=e74] [cursor=pointer]:
            - img [ref=e75]
            - generic [ref=e77]: Open Guard Cloud
            - img [ref=e78]
          - link "Report a bug" [ref=e81] [cursor=pointer]:
            - /url: https://github.com/hashgraph-online/hol-guard/issues/new?title=%5BBug%5D%3A+&body=%23%23+What+happened%3F%0A%0A%0A%23%23+Expected+behavior%0A%0A%0A%23%23+Steps+to+reproduce%0A1.%0A2.%0A3.%0A%0A%23%23+Environment%0A-+HOL+Guard+version%3A%0A-+OS%3A%0A-+AI+app+or+harness%3A%0A%0A%23%23+Anything+else%3F%0A&labels=bug%2Cneeds-triage
            - img [ref=e82]
            - generic [ref=e84]: Report a bug
            - img [ref=e85]
        - generic [ref=e89]:
          - generic [ref=e90]:
            - img [ref=e91]
            - generic [ref=e93]: Local Guard
            - strong [ref=e94]: Clear
          - paragraph [ref=e96]: No local approvals are waiting.
          - generic [ref=e98]:
            - generic "Guard version unknown" [ref=e100]: vunknown
            - button "Try alpha updates" [ref=e101] [cursor=pointer]:
              - img [ref=e102]
              - generic [ref=e104]: Try alpha updates
    - generic [ref=e105]:
      - main [ref=e106]:
        - generic [ref=e109]:
          - generic [ref=e111]:
            - generic [ref=e112]:
              - paragraph [ref=e113]: On this device
              - heading "Extensions" [level=1] [ref=e114]
              - paragraph [ref=e115]: Choose an Extension to review its permissions and effective protection.
            - link "Sponsor an extension" [ref=e118] [cursor=pointer]:
              - /url: https://hol.org/guard/extensions/advertise?source=guard_local&intent=extension-promotion&placement=extensions_header
          - generic [ref=e119]:
            - region "Protected" [ref=e121]:
              - img [ref=e123]
              - generic [ref=e126]:
                - paragraph [ref=e127]: Local protection
                - heading "Protected" [level=2] [ref=e128]
                - paragraph [ref=e129]: Guard is actively applying the trusted protection settings on this device.
              - generic [ref=e130]:
                - img [ref=e131]
                - text: No action required
            - alert [ref=e134]: Invalid local CLI revision
            - region "Featured by their makers" [ref=e135]:
              - generic [ref=e136]:
                - heading "Featured by their makers" [level=2] [ref=e137]
                - paragraph [ref=e138]: Paid placements are labeled. They change position here, never your protection.
              - generic [ref=e139]:
                - article [ref=e140]:
                  - generic [ref=e141]:
                    - img [ref=e144]
                    - generic [ref=e146]:
                      - generic [ref=e147]:
                        - generic [ref=e148]: Sponsored · Featured
                        - generic [ref=e149]: Paid for by Northwind Tools
                      - heading "Northwind Tools headline" [level=3] [ref=e150]
                      - paragraph [ref=e151]: github
                  - paragraph [ref=e152]: Paid creative body copy.
                  - generic [ref=e153]:
                    - button "View extension" [ref=e154] [cursor=pointer]:
                      - text: View extension
                      - img [ref=e155]
                    - paragraph [ref=e157]: Paid placement. Your protection settings are unchanged.
                - article [ref=e158]:
                  - generic [ref=e159]:
                    - generic [ref=e160]:
                      - img [ref=e162]
                      - img [ref=e165]
                    - generic [ref=e167]:
                      - generic [ref=e168]:
                        - generic [ref=e169]: Sponsored · Featured
                        - generic [ref=e170]: Paid for by Harbor Labs
                      - heading "Harbor Labs headline" [level=3] [ref=e171]
                      - paragraph [ref=e172]: package.node
                  - paragraph [ref=e173]: Paid creative body copy.
                  - generic [ref=e174]:
                    - button "View extension" [ref=e175] [cursor=pointer]:
                      - text: View extension
                      - img [ref=e176]
                    - paragraph [ref=e178]: Paid placement. Your protection settings are unchanged.
                - article [ref=e179]:
                  - generic [ref=e180]:
                    - img [ref=e183]
                    - generic [ref=e185]:
                      - generic [ref=e186]:
                        - generic [ref=e187]: Sponsored · Featured
                        - generic [ref=e188]: Paid for by Tidewater
                      - heading "Tidewater headline" [level=3] [ref=e189]
                      - paragraph [ref=e190]: package.python
                  - paragraph [ref=e191]: Paid creative body copy.
                  - generic [ref=e192]:
                    - button "View extension" [ref=e193] [cursor=pointer]:
                      - text: View extension
                      - img [ref=e194]
                    - paragraph [ref=e196]: Paid placement. Your protection settings are unchanged.
              - paragraph [ref=e197]: Sponsored placements, when present, are labeled and never change protection.
            - region "Search command patterns" [ref=e199]:
              - heading "Search command patterns" [level=2] [ref=e200]
              - generic [ref=e202]:
                - generic [ref=e203]:
                  - generic [ref=e204]: Search command patterns
                  - img
                  - searchbox "Search command patterns" [ref=e205]
                - button "Filters" [ref=e207] [cursor=pointer]:
                  - img [ref=e208]
                  - text: Filters
                  - img [ref=e210]
              - paragraph [ref=e212]: Matches patterns across every tool. Press / to focus search from anywhere on this page.
            - region "Custom extensions" [ref=e213]:
              - generic [ref=e215]:
                - heading "Custom extensions" [level=2] [ref=e216]
                - paragraph [ref=e217]: Connectors Guard detected in your apps, plus tools you add yourself. Open one to choose its permissions.
              - generic [ref=e219]:
                - paragraph [ref=e220]: Could not check host configuration. Known connections remain available. Could not read Codex app inventory. Known connections remain available.
                - button "Check for connectors again" [ref=e221] [cursor=pointer]
              - generic [ref=e222]:
                - paragraph [ref=e223]: No custom extensions yet.
                - paragraph [ref=e224]: Add a tool you run yourself or connect an MCP server. Connectors in your host apps appear here automatically.
                - button "Add custom extension" [ref=e225] [cursor=pointer]:
                  - img [ref=e226]
                  - text: Add custom extension
            - region "All tools" [ref=e228]:
              - generic [ref=e229]:
                - generic [ref=e230]:
                  - heading "All tools" [level=2] [ref=e231]
                  - paragraph [ref=e232]: Every built-in tool Guard can watch on this device. Open one to adjust its command patterns.
                - generic [ref=e234]: 10 tools
              - generic [ref=e235]:
                - img "10 on" [ref=e236]
                - list "Catalog status" [ref=e238]:
                  - listitem [ref=e239]:
                    - generic "Guard allows this tool" [ref=e240]:
                      - generic [ref=e242]: "Status:"
                      - text: "On"
                    - generic [ref=e243]: "10"
              - generic [ref=e244]:
                - generic [ref=e245]:
                  - generic [ref=e246]:
                    - generic [ref=e247]: Sponsored · Featured
                    - generic [ref=e248]: Paid for by Northwind Tools
                    - generic [ref=e249]: Northwind Tools headline
                  - 'button "github github 1 rule · 1 permission · by Hashgraph Online Status: On" [ref=e250] [cursor=pointer]':
                    - img [ref=e253]
                    - generic [ref=e255]:
                      - strong [ref=e257]: github
                      - generic [ref=e258]: github
                      - generic [ref=e259]: 1 rule · 1 permission · by Hashgraph Online
                    - generic "Guard allows this tool" [ref=e260]:
                      - generic [ref=e262]: "Status:"
                      - text: "On"
                    - img [ref=e263]
                - generic [ref=e265]:
                  - generic [ref=e266]:
                    - generic [ref=e267]: Sponsored · Featured
                    - generic [ref=e268]: Paid for by Harbor Labs
                    - generic [ref=e269]: Harbor Labs headline
                  - 'button "package.node package.node 1 rule · 1 permission · by Hashgraph Online Status: On" [ref=e270] [cursor=pointer]':
                    - generic [ref=e271]:
                      - img [ref=e273]
                      - img [ref=e276]
                    - generic [ref=e278]:
                      - strong [ref=e280]: package.node
                      - generic [ref=e281]: package.node
                      - generic [ref=e282]: 1 rule · 1 permission · by Hashgraph Online
                    - generic "Guard allows this tool" [ref=e283]:
                      - generic [ref=e285]: "Status:"
                      - text: "On"
                    - img [ref=e286]
                - generic [ref=e288]:
                  - generic [ref=e289]:
                    - generic [ref=e290]: Sponsored · Featured
                    - generic [ref=e291]: Paid for by Tidewater
                    - generic [ref=e292]: Tidewater headline
                  - 'button "package.python package.python 1 rule · 1 permission · by Hashgraph Online Status: On" [ref=e293] [cursor=pointer]':
                    - img [ref=e296]
                    - generic [ref=e298]:
                      - strong [ref=e300]: package.python
                      - generic [ref=e301]: package.python
                      - generic [ref=e302]: 1 rule · 1 permission · by Hashgraph Online
                    - generic "Guard allows this tool" [ref=e303]:
                      - generic [ref=e305]: "Status:"
                      - text: "On"
                    - img [ref=e306]
                - generic [ref=e308]:
                  - generic [ref=e309]:
                    - generic [ref=e310]: Sponsored · Featured
                    - generic [ref=e311]: Paid for by Tidewater
                    - generic [ref=e312]: Tidewater headline
                  - 'button "package.python package.python 1 rule · 1 permission · by Hashgraph Online Status: On" [ref=e313] [cursor=pointer]':
                    - img [ref=e316]
                    - generic [ref=e318]:
                      - strong [ref=e320]: package.python
                      - generic [ref=e321]: package.python
                      - generic [ref=e322]: 1 rule · 1 permission · by Hashgraph Online
                    - generic "Guard allows this tool" [ref=e323]:
                      - generic [ref=e325]: "Status:"
                      - text: "On"
                    - img [ref=e326]
                - 'button "container runtime container-runtime 1 rule · 1 permission · by Hashgraph Online Status: On" [ref=e328] [cursor=pointer]':
                  - img [ref=e331]
                  - generic [ref=e333]:
                    - strong [ref=e335]: container runtime
                    - generic [ref=e336]: container-runtime
                    - generic [ref=e337]: 1 rule · 1 permission · by Hashgraph Online
                  - generic "Guard allows this tool" [ref=e338]:
                    - generic [ref=e340]: "Status:"
                    - text: "On"
                  - img [ref=e341]
                - 'button "database.postgresql database.postgresql 1 rule · 1 permission · by Hashgraph Online Status: On" [ref=e343] [cursor=pointer]':
                  - img [ref=e346]
                  - generic [ref=e348]:
                    - strong [ref=e350]: database.postgresql
                    - generic [ref=e351]: database.postgresql
                    - generic [ref=e352]: 1 rule · 1 permission · by Hashgraph Online
                  - generic "Guard allows this tool" [ref=e353]:
                    - generic [ref=e355]: "Status:"
                    - text: "On"
                  - img [ref=e356]
                - generic [ref=e358]:
                  - img [ref=e360]
                  - generic [ref=e362]:
                    - paragraph [ref=e363]: Your extension could be listed here.
                    - paragraph [ref=e364]: A sponsored listing keeps its real protection state and its Sponsored label. Position is all it buys.
                  - link "Get a listing · from $49/mo" [ref=e365] [cursor=pointer]:
                    - /url: https://hol.org/guard/extensions/advertise?source=guard_local&intent=extension-promotion&placement=extensions_feed
                    - text: Get a listing · from $49/mo
                    - img [ref=e366]
                - 'button "filesystem filesystem 1 rule · 1 permission · by Hashgraph Online Status: On" [ref=e369] [cursor=pointer]':
                  - img [ref=e371]
                  - generic [ref=e373]:
                    - strong [ref=e375]: filesystem
                    - generic [ref=e376]: filesystem
                    - generic [ref=e377]: 1 rule · 1 permission · by Hashgraph Online
                  - generic "Guard allows this tool" [ref=e378]:
                    - generic [ref=e380]: "Status:"
                    - text: "On"
                  - img [ref=e381]
                - 'button "Git git 1 rule · 1 permission · by Hashgraph Online Status: On" [ref=e383] [cursor=pointer]':
                  - img [ref=e386]
                  - generic [ref=e388]:
                    - strong [ref=e390]: Git
                    - generic [ref=e391]: git
                    - generic [ref=e392]: 1 rule · 1 permission · by Hashgraph Online
                  - generic "Guard allows this tool" [ref=e393]:
                    - generic [ref=e395]: "Status:"
                    - text: "On"
                  - img [ref=e396]
                - 'button "kubernetes operations kubernetes-operations 1 rule · 1 permission · by Hashgraph Online Status: On" [ref=e398] [cursor=pointer]':
                  - generic [ref=e399]:
                    - img [ref=e401]
                    - img [ref=e404]
                  - generic [ref=e406]:
                    - strong [ref=e408]: kubernetes operations
                    - generic [ref=e409]: kubernetes-operations
                    - generic [ref=e410]: 1 rule · 1 permission · by Hashgraph Online
                  - generic "Guard allows this tool" [ref=e411]:
                    - generic [ref=e413]: "Status:"
                    - text: "On"
                  - img [ref=e414]
                - 'button "remote.ssh remote.ssh 1 rule · 1 permission · by Hashgraph Online Status: On" [ref=e416] [cursor=pointer]':
                  - img [ref=e418]
                  - generic [ref=e420]:
                    - strong [ref=e422]: remote.ssh
                    - generic [ref=e423]: remote.ssh
                    - generic [ref=e424]: 1 rule · 1 permission · by Hashgraph Online
                  - generic "Guard allows this tool" [ref=e425]:
                    - generic [ref=e427]: "Status:"
                    - text: "On"
                  - img [ref=e428]
            - group [ref=e430]:
              - generic "Local skills and workflows" [ref=e431] [cursor=pointer]
      - contentinfo [ref=e432]:
        - generic [ref=e433]:
          - paragraph [ref=e434]:
            - text: HOL Guard is open source under
            - link "Apache-2.0" [ref=e435] [cursor=pointer]:
              - /url: https://github.com/hashgraph-online/hol-guard/blob/main/LICENSE
            - text: .
          - navigation "Guard resources" [ref=e436]:
            - link "Docs" [ref=e437] [cursor=pointer]:
              - /url: https://hol.org/guard/docs
            - link "Guard Cloud" [ref=e438] [cursor=pointer]:
              - /url: https://hol.org/guard
            - link "GitHub" [ref=e439] [cursor=pointer]:
              - /url: https://github.com/hashgraph-online/hol-guard
            - link "Report a bug" [ref=e440] [cursor=pointer]:
              - /url: https://github.com/hashgraph-online/hol-guard/issues/new?title=%5BBug%5D%3A+&body=%23%23+What+happened%3F%0A%0A%0A%23%23+Expected+behavior%0A%0A%0A%23%23+Steps+to+reproduce%0A1.%0A2.%0A3.%0A%0A%23%23+Environment%0A-+HOL+Guard+version%3A%0A-+OS%3A%0A-+AI+app+or+harness%3A%0A%0A%23%23+Anything+else%3F%0A&labels=bug%2Cneeds-triage
```

# Test source

```ts
  134 |     // Vacant shelf must not also run the in-feed ask.
  135 |     await expect(page.getByTestId("catalog-slot-row")).toHaveCount(0);
  136 | 
  137 |     await expectRendersAtBothSizes(page, async () => {
  138 |       await expect(spotlight).toBeVisible();
  139 |       await expect(slot).toBeVisible();
  140 |     });
  141 |   });
  142 | 
  143 |   test("a fresh device falls back to the starter set without inventing metrics", async ({ page }) => {
  144 |     await mount(page, { catalog: wideCatalog() });
  145 |     await routeDiscovery(page, projection({ shelf: "unknown", listing: "unknown" }));
  146 |     await routeAnalytics(page, []);
  147 |     await initialize(page);
  148 | 
  149 |     await expect(page.getByRole("heading", { name: "Good places to start" })).toBeVisible();
  150 |     await expect(page.getByTestId("spotlight-basis")).toContainText("Not a ranking or a popularity measure");
  151 |     await expect(page.getByTestId("spotlight-organic-card")).toHaveCount(3);
  152 |     await expect(page.getByTestId("spotlight-organic-card").first()).toHaveAttribute("data-basis", "starter");
  153 |     // Availability the server could not confirm never becomes a sales pitch.
  154 |     await expect(page.getByTestId("spotlight-slot-card")).toHaveCount(0);
  155 |   });
  156 | 
  157 |   test("sold placement leads the shelf, stays labeled, and opens the in-feed ask", async ({ page }) => {
  158 |     await mount(page, { catalog: wideCatalog() });
  159 |     await routeDiscovery(page, projection({
  160 |       placements: [
  161 |         placement("command.cloud.aws", "always", "Northwind Tools"),
  162 |         placement("command.github", "sponsored", "Harbor Labs"),
  163 |       ],
  164 |     }));
  165 |     await routeAnalytics(page, [{ value: "command.git", count: 41 }]);
  166 |     await initialize(page);
  167 | 
  168 |     const featured = page.getByTestId("discovery-featured-card");
  169 |     await expect(featured).toHaveCount(1);
  170 |     await expect(featured).toContainText("Northwind Tools");
  171 |     await expect(featured).toContainText("Paid placement. Your protection settings are unchanged.");
  172 |     await expect(page.getByTestId("discovery-sponsored-card")).toContainText("Harbor Labs");
  173 |     await expect(page.getByRole("heading", { name: "Featured by their makers" })).toBeVisible();
  174 |     // With inventory proven to exist, the one inline ask appears in the list.
  175 |     const inFeed = page.getByTestId("catalog-slot-row");
  176 |     await expect(inFeed).toHaveCount(1);
  177 |     await expect(inFeed).toContainText("Position is all it buys.");
  178 |     await expect(inFeed.getByRole("link", { name: /Get a listing · from \$49\/mo/ })).toBeVisible();
  179 | 
  180 |     await expectRendersAtBothSizes(page, async () => {
  181 |       await expect(featured).toBeVisible();
  182 |       await expect(inFeed).toBeVisible();
  183 |     });
  184 |   });
  185 | 
  186 |   test("a sold-out shelf is silent, and a sold-out listing never borrows an open price", async ({ page }) => {
  187 |     await mount(page, { catalog: wideCatalog() });
  188 |     await routeDiscovery(page, projection({ shelf: "sold_out", listing: "sold_out", placements: [placement("command.cloud.aws", "always", "Northwind Tools")] }));
  189 |     await routeAnalytics(page, [{ value: "command.git", count: 41 }]);
  190 |     await initialize(page);
  191 | 
  192 |     await expect(page.getByTestId("discovery-featured-card")).toHaveCount(1);
  193 |     // Nothing is for sale, so nothing asks: no cell, no row, no sold-out claim
  194 |     // sitting beside organic cards.
  195 |     await expect(page.getByTestId("spotlight-slot-card")).toHaveCount(0);
  196 |     await expect(page.getByTestId("catalog-slot-row")).toHaveCount(0);
  197 |   });
  198 | 
  199 |   test("a sponsored placement past the shelf still gets its labeled catalog row", async ({ page }) => {
  200 |     await mount(page, { catalog: wideCatalog() });
  201 |     await routeDiscovery(page, projection({
  202 |       placements: [
  203 |         placement("command.cloud.aws", "always", "Northwind Tools"),
  204 |         placement("command.github", "always", "Harbor Labs"),
  205 |         placement("command.package.node", "always", "Tidewater"),
  206 |         placement("command.remote.ssh", "sponsored", "Fourth Buyer"),
  207 |       ],
  208 |     }));
  209 |     await routeAnalytics(page, []);
  210 |     await initialize(page);
  211 | 
  212 |     // The shelf holds three; the fourth buyer is disclosed in the catalog.
  213 |     await expect(page.getByTestId("discovery-featured-card")).toHaveCount(3);
  214 |     const rows = page.getByTestId("catalog-featured-row");
  215 |     await expect(rows.filter({ hasText: "Fourth Buyer" })).toHaveCount(1);
  216 |     await expect(rows.filter({ hasText: "Fourth Buyer" })).toContainText("Sponsored");
  217 |   });
  218 | 
  219 |   test("a sponsored row ordered ahead of the featured ones is still rendered once each", async ({ page }) => {
  220 |     await mount(page, { catalog: wideCatalog() });
  221 |     await routeDiscovery(page, projection({
  222 |       placements: [
  223 |         placement("command.github", "always", "Northwind Tools"),
  224 |         placement("command.package.node", "always", "Harbor Labs"),
  225 |         placement("command.package.python", "always", "Tidewater"),
  226 |         // Sorts ahead of every featured id, which is what breaks a count-based split.
  227 |         placement("command.cloud.aws", "sponsored", "Fourth Buyer"),
  228 |       ],
  229 |     }));
  230 |     await routeAnalytics(page, []);
  231 |     await initialize(page);
  232 | 
  233 |     const rows = page.getByTestId("catalog-featured-row");
> 234 |     await expect(rows.filter({ hasText: "Fourth Buyer" })).toHaveCount(1);
      |                                                            ^ Error: expect(locator).toHaveCount(expected) failed
  235 |     await expect(rows.filter({ hasText: "Tidewater" })).toHaveCount(1);
  236 |     await expect(rows).toHaveCount(4);
  237 |   });
  238 | 
  239 |   test("one surface: no tab strip, and searching hides the shelf", async ({ page }) => {
  240 |     await mount(page, { catalog: wideCatalog() });
  241 |     await routeDiscovery(page, projection());
  242 |     await routeAnalytics(page, [{ value: "command.git", count: 12 }]);
  243 |     await initialize(page);
  244 | 
  245 |     await expect(page.getByTestId("extensions-surface")).toBeVisible();
  246 |     await expect(page.getByRole("tablist")).toHaveCount(0);
  247 |     await expect(page.getByTestId("extensions-spotlight")).toBeVisible();
  248 | 
  249 |     await page.getByRole("searchbox").first().fill("github");
  250 |     await expect(page.getByTestId("extensions-spotlight")).toHaveCount(0);
  251 |     await expect(page.getByTestId("catalog-slot-row")).toHaveCount(0);
  252 |   });
  253 | });
  254 | 
```