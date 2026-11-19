"""Planted bugs for tools/mutate.py. One entry = one exact replacement in one file.

file: path under go/; pkg: the package whose tests run; run: the go test -run pattern;
equivalent: a reason string when the bug cannot change observable behaviour (a survivor that is
not marked equivalent means the corpus has a gap)."""

MUTANTS = []


def m(file, old, new, run, equivalent=None, pkg=None):
    # pkg: the package whose tests run; for shared packages (config, bashcompat) it is the package
    # whose corpus exercises the code, so it must be given (default: the file's own package)
    if pkg is None:
        pkg = PKG_OVERRIDE.get(file) or (file.split("/")[1] if file.startswith("internal/") else "")
    MUTANTS.append(dict(file=file, old=old, new=new, run=run, pkg=pkg, equivalent=equivalent))


PKG_OVERRIDE = {
    "internal/config/config.go": "gate",
    "internal/bashcompat/bashcompat.go": "gate",
}

ENC = "internal/gate/encrypted.go"
R_ENC = "TestGolden|TestBashSuiteAssertions"
m(ENC, "s := sc - 1 // legacy", "s := sc // legacy", R_ENC)
m(ENC, "if s > float64(bopen) && ec < float64(bclose) {", "if s >= float64(bopen) && ec < float64(bclose) {", R_ENC)
m(ENC, "if s > float64(bopen) && ec < float64(bclose) {", "if s > float64(bopen) && ec <= float64(bclose) {", R_ENC)
m(ENC, "bopen := estart + 3", "bopen := estart + 2", R_ENC)
m(ENC, "bclose := bopen + closeRel - 1", "bclose := bopen + closeRel", R_ENC)
m(ENC, "if closeRel == 0 {\n\t\t\t\tpos = estart + 1\n\t\t\t\tcontinue\n\t\t\t}", "", R_ENC,
  equivalent="with no closing bracket the envelope end is before its start, so no span can sit inside it")
m(ENC, "pos = estart + 1\n\t\t}\n\t}\n\treturn false", "pos = estart + 2\n\t\t}\n\t}\n\treturn false", R_ENC,
  equivalent="restarting one byte later cannot overlap the marker with itself")
m(ENC, "if digitsOnly.MatchString(startcol) && digitsOnly.MatchString(endcol) {", "if digitsOnly.MatchString(startcol) || digitsOnly.MatchString(endcol) {", R_ENC)
m(ENC, "if !digitsOnly.MatchString(line) {", "if false {", R_ENC)
m(ENC, "if tt == \"\" || tt[0] == '#' {", "if tt == \"\" {", R_ENC)
m(ENC, "for pos < L && s[pos] == '-' && (pos+2 > L || s[pos+1] == ' ') {", "for pos < L && s[pos] == '-' {", R_ENC)
m(ENC, "if info[j].cind < tInd {", "if info[j].cind <= tInd {", R_ENC)
m(ENC, "if p < 0 || info[p].key != \"encryptedData\" {", "if p < 0 {", R_ENC)
m(ENC, "if gp < 0 || info[gp].key != \"spec\" {", "if gp < 0 {", R_ENC)
m(ENC, "if info[j].cind == specInd && info[j].item {", "if info[j].cind == specInd {", R_ENC)
m(ENC, "return kindOK && apiOK", "return kindOK || apiOK", R_ENC)
m(ENC, "if info[j].key == \"kind\" && sealedKindVal.MatchString(info[j].val) {", "if info[j].key == \"kind\" {", R_ENC)
m(ENC, "if info[j].blank || info[j].cind != specInd || !info[j].iskey {", "if info[j].blank || !info[j].iskey {", R_ENC)
m(ENC, "docSeparator = regexp.MustCompile(`^(---|\\.\\.\\.)([[:space:]].*)?$`)", "docSeparator = regexp.MustCompile(`^---([[:space:]].*)?$`)", R_ENC)
m(ENC, "if info[t].blank {", "if false {", R_ENC,
  equivalent="a blank target is also rejected by the parent search that follows")
m(ENC, "keyLine = regexp.MustCompile(`(?s)^[^[:space:]#][^:]*:([[:space:]].*)?$`)", "keyLine = regexp.MustCompile(`(?s)^[^[:space:]#].*:([[:space:]].*)?$`)", R_ENC)

MSK = "internal/gate/masked.go"
R_MSK = "TestMaskedGolden"
m(MSK, '".env", ".env.local", ".npmrc"', '".env", ".npmrc"', R_MSK)
m(MSK, "relpath == maskedDirPath ||", "false ||", R_MSK)
m(MSK, 'maskedDirPath+"/")', "maskedDirPath)", R_MSK)
m(MSK, '!strings.Contains(relpath, "/") &&', "", R_MSK)
m(MSK, "strings.HasSuffix(relpath, maskedOpenrcSuffix)", 'strings.HasSuffix(relpath, "openrc.sh")', R_MSK)
m(MSK, 'if relpath == d || strings.HasPrefix(relpath, d+"/") {', 'if strings.HasPrefix(relpath, d+"/") {', R_MSK)
m(MSK, 'if relpath == d || strings.HasPrefix(relpath, d+"/") {', "if relpath == d || strings.HasPrefix(relpath, d) {", R_MSK)

CFG = "internal/config/config.go"
R_CFG = "TestListsGolden|TestMaskedGolden"
m(CFG, 'if strings.HasPrefix(line, key+":") {\n\t\t\tflag = true', "if strings.HasPrefix(line, key) {\n\t\t\tflag = true", R_CFG)
m(CFG, "(c >= 'A' && c <= 'Z') || ", "", R_CFG)
m(CFG, "c == '_' || ", "", R_CFG)
m(CFG, "if !deviation.Fixed(deviation.EchoOptionItems) && echoOption.MatchString(line) {", "if false {", R_CFG)
m(CFG, "if !deviation.Fixed(deviation.EchoOptionItems) && echoOption.MatchString(item) {", "if false {", R_CFG)
m(CFG, "if isSpace(item[i]) && item[i+1] == '#' {", "if item[i] == ' ' && item[i+1] == '#' {", R_CFG)
m(CFG, 'item = strings.TrimRight(item, " \\t\\n\\v\\f\\r")', 'item = strings.TrimRight(item, " ")', R_CFG)
m(CFG, 'item = strings.NewReplacer(`"`, "", `\'`, "").Replace(item)', 'item = strings.NewReplacer(`"`, "").Replace(item)', R_CFG)
m(CFG, "if item == \"\" || item[0] == '#' {", 'if item == "" {', R_CFG)
m(CFG, "flag = true\n\t\t\tcontinue", "flag = true", R_CFG)
R_SCAN = "TestScanGolden"
m(CFG, "raw = e.Home + raw[1:]", "raw = raw[1:]", R_SCAN)
m(CFG, "if loc := reTrailComment.FindStringIndex(line); loc != nil {", "if loc := reTrailComment.FindStringIndex(line); false && loc != nil {", R_SCAN)
m(CFG, "line = strings.NewReplacer(`\"`, \"\", `'`, \"\").Replace(line)", "line = strings.NewReplacer(`\"`, \"\").Replace(line)", R_SCAN)

ACC = "internal/gate/accepted.go"
R_ACC = "TestAcceptedGolden"
m(ACC, "st.Size() == 0", "false", R_ACC)
m(ACC, "if l == p {", "if strings.Contains(l, p) {", R_ACC)
m(ACC, "if !found {\n\t\treturn false\n\t}", "", R_ACC)
m(ACC, '"--", spec)', "spec)", R_ACC)
m(ACC, 'strings.TrimSuffix(string(data), "\\n")', "strings.TrimSpace(string(data))", R_ACC)
m(ACC, 'acceptFile == ""', "false", R_ACC, equivalent="os.Stat of an empty path fails anyway")

SC = "internal/gate/scan.go"
m(SC, 'strings.HasPrefix(entry, "../") || strings.Contains(entry, "/../")', 'strings.Contains(entry, "/../")', R_SCAN)
m(SC, '|| strings.Contains(entry, "/../") {', "{", R_SCAN)
m(SC, "[]string{repoIgnoreName, repoIgnoreFallback}", "[]string{repoIgnoreName}", R_SCAN)
m(SC, 'if strings.HasPrefix(relpath, ".git/") {', "if false {", R_SCAN)
m(SC, "case IsPathMasked(repo, relpath):", "case IsPathMasked(realRepo, relpath):", R_SCAN, equivalent="realRepo is the same directory as repo")
m(SC, 'class = "sealed"', 'class = "yes"', R_SCAN)
m(SC, "if config.IsFile(gitcfg) {", "if true {", R_SCAN)
m(SC, "honorInline == \"no\" || !inlineAllowEnabled(e)", "honorInline == \"no\" && !inlineAllowEnabled(e)", R_SCAN)
m(SC, "honorInline == \"no\" || !inlineAllowEnabled(e)", "!inlineAllowEnabled(e)", R_SCAN)
m(SC, "if cur := sha256File(cache); cur != \"\" && cur == pin {", 'if cur := sha256File(cache); cur != "" {', R_SCAN)
m(SC, 'config.IsFile(cache) && pin != "" && src == url', 'config.IsFile(cache) && pin != ""', R_SCAN)
m(SC, '[]string{"betterleaks.toml", ".betterleaks.toml"}', '[]string{"betterleaks.toml"}', R_SCAN)
m(SC, 'for _, f := range []string{".betterleaksignore", ".gitleaksignore"} {', 'for _, f := range []string{".gitleaksignore", ".betterleaksignore"} {', R_SCAN)
m(SC, 'paths = append(paths, "(^|/)"+LeakscanRegexEscape(d)+"(/|$)")', 'paths = append(paths, "(^|/)"+d+"(/|$)")', R_SCAN)
m(SC, 'paths = append(paths, "(^|/)"+LeakscanRegexEscape(sp)+"$")', 'paths = append(paths, "(^|/)"+sp+"$")', R_SCAN)
m(SC, 'base = d[i+1:]', "base = d", R_SCAN)
m(SC, "if !exclusionsEnabled(e, repo) {", "if false {", R_SCAN)
m(SC, 'v = config.ExtractYAMLScalar(e.UserConfig, "leakscan_dep_exclusions")', 'v = ""', R_SCAN)
m(SC, 'case "off", "false", "no", "0", "OFF", "False", "FALSE", "No", "NO":', 'case "off", "false", "no", "0":', R_SCAN)
m(SC, 'if x != "" {\n\t\t\t\tdep = append(dep, x)', 'if false {\n\t\t\t\tdep = append(dep, x)', R_SCAN)
m(SC, "if rc == 1 {\n\t\tb, _ := os.ReadFile(report)", "if rc >= 1 && rc < 3 {\n\t\tb, _ := os.ReadFile(report)", R_SCAN)
m(SC, "_, isArr := last.([]any)", "_, isArr := last.([]any); isArr = true", R_SCAN)
m(SC, 'case nil:\n\t\treturn "null"', 'case nil:\n\t\treturn ""', R_SCAN)
m(SC, "break elem\n\t\t\t}\n\t\t\trow := make", "continue elem\n\t\t\t}\n\t\t\trow := make", R_SCAN)
m(SC, 'strings.NewReplacer("\\\\", "\\\\\\\\", "\\t", "\\\\t", "\\n", "\\\\n", "\\r", "\\\\r")', 'strings.NewReplacer("\\t", "\\\\t", "\\n", "\\\\n", "\\r", "\\\\r")', R_SCAN)
m(SC, 'args = append(args, "ionice", "-c3")', 'args = append(args, "ionice", "-c2")', R_SCAN, equivalent="the stub never sees the nice/ionice arguments")
m(SC, "rc = 127", "rc = 1", R_SCAN, equivalent="needs a missing nice binary")
BC = "internal/bashcompat/bashcompat.go"
m(BC, 's := strings.TrimLeft(line, "\\t")', "s := line", R_SCAN)
m(BC, 'out[n-1] = strings.TrimRight(s, "\\t")', "out[n-1] = s", R_SCAN, equivalent="@tsv escaping leaves no trailing tab")

SG = "internal/gate/secretgate.go"
R_SG = "TestGateGolden"
m(SG, "if len(repos) == 0 {", "if len(repos) < 0 {", R_SG)
m(SG, 'strings.TrimRight(d.LoadRepoAcceptedSecrets(repo), "\\n") != ""', 'd.LoadRepoAcceptedSecrets(repo) != ""', R_SG)
m(SG, 'if relpath == "" {\n\t\t\t\tcontinue\n\t\t\t}', "", R_SG, equivalent="unreachable while tab fields collapse (legacy)")
m(SG, "case \"yes\":\n\t\t\t\ttotalMasked++", "case \"yes\":\n\t\t\t\ttotalEncrypted++", R_SG)
m(SG, "if d.ExceptionsFromCommit() {", "if !d.ExceptionsFromCommit() {", R_SG)
m(SG, 'if strings.TrimSpace(r) == "" || seen[r] {', 'if strings.TrimSpace(r) == "" {', R_SG)
m(SG, 'if accept == "true" {', 'if accept != "false" {', R_SG)
m(SG, 'if endpointTrusted == "true" && d.IsTTY {', 'if endpointTrusted == "true" {', R_SG)
m(SG, 'if endpointTrusted == "true" && d.IsTTY {', 'if endpointTrusted != "false" && d.IsTTY {', R_SG)
m(SG, 'reply = strings.Trim(strings.TrimSuffix(line, "\\n"), " \\t")', 'reply = strings.TrimSuffix(line, "\\n")', R_SG)
m(SG, "(reply[0] == 'y' || reply[0] == 'Y')", "(reply[0] == 'y')", R_SG)
m(SG, "return 1, summary\n\t}\n\n\te(\"\", \"ERROR: betterleaks found", "return 0, summary\n\t}\n\n\te(\"\", \"ERROR: betterleaks found", R_SG)
m(SG, "if f[0] != repo || contains(seenPaths, f[1]) {", "if f[0] != repo {", R_SG)
m(SG, "case match == \"\":", "case false:", R_SG)
m(SG, 'case strings.Contains(match, "REDACTED"):', 'case match == "REDACTED":', R_SG)
m(SG, "os.Remove(af.Name())\n\t\t\t\te(\"\",", "e(\"\",", R_SG, equivalent="temp-file cleanup is not observable")
m(BC, 'special := strings.IndexByte(" !\\"$&\'()*,;<>?[\\\\]^`{|}", c) >= 0', 'special := strings.IndexByte(" !\\"$&\'()*;<>?[\\\\]^`{|}", c) >= 0', R_SG)
m(BC, "if c == '~' && (i == 0 || s[i-1] == ':' || s[i-1] == '=') {", "if c == '~' && i == 0 {", R_SG)

# ---- vetting
VC = "internal/vetting/config.go"
R_VC = "TestConfigGolden"
m(VC, "case \"off\":\n\t\treturn 0", "case \"off\":\n\t\treturn 2", R_VC)
m(VC, "overlayP != \"\" && rank(overlayP) > rank(eff)", 'overlayP != ""', R_VC)
m(VC, "userP := c.normalize(c.userGet(\"vetting\"))", 'userP := c.userGet("vetting")', R_VC)
m(VC, "if c.userGet(key) == \"true\" || c.overlayGet(key) == \"true\" {", 'if c.userGet(key) == "true" {', R_VC)
m(VC, "if c.userGet(key) == \"true\" || c.overlayGet(key) == \"true\" {", 'if c.userGet(key) == "true" && c.overlayGet(key) == "true" {', R_VC)
m(VC, "if config.Exists(userRoot) {", "if true {", R_VC)
m(VC, "if config.Exists(v) && v != userRoot {", "if config.Exists(v) {", R_VC)
m(VC, "if !strings.HasPrefix(v, \"/\") {", "if false {", R_VC)
m(VC, "switch v := c.configGet(\"vetting_trust_format\"); v {", 'switch v := c.userGet("vetting_trust_format"); v {', R_VC)
m(VC, 'func (c Ctx) SigningKey() string { return c.tilde(c.userGet("vetting_signing_key")) }', 'func (c Ctx) SigningKey() string { return c.tilde(c.configGet("vetting_signing_key")) }', R_VC)
m(VC, "if !digits.MatchString(v) {\n\t\t\tcontinue", 'if v == "" {\n\t\t\tcontinue', R_VC)
m(VC, "if eff == \"\" || bashcompat.ArithLess(v, eff) {", 'if eff == "" || v < eff {', R_VC)
m(VC, "if eff == \"\" || bashcompat.ArithLess(v, eff) {", 'if eff == "" {', R_VC)
m(VC, "if e > now {", "if e >= now {", R_VC, equivalent="a timestamp equal to now has age 0 either way")
m(VC, "return itoa((now - e) / 86400)", "return itoa((now - e + 86399) / 86400)", R_VC)
m("internal/bashcompat/bashcompat.go", "if len(s) > 1 && s[0] == '0' {", "if false {", R_VC, pkg="vetting")
m("internal/bashcompat/bashcompat.go", "if d >= base {", "if d >= 10 {", R_VC, pkg="vetting")

VF = "internal/vetting/verify.go"
R_VF = "TestVerifyGolden"
m(VF, '"-c", "core.fsmonitor=", "-c", "core.hooksPath=/dev/null"}, args...)', '"-c", "core.hooksPath=/dev/null"}, args...)', R_VF)
m(VF, 'env = append(env, fmt.Sprintf("GIT_CONFIG_COUNT=%d", n))', 'env = append(env, "GIT_CONFIG_COUNT=0")', R_VF)
m(VF, 'if m := filterNameRe.FindStringSubmatch(l); m != nil {', 'if m := filterNameRe.FindStringSubmatch(l); false && m != nil {', R_VF)
m(VF, 'filterNameRe = regexp.MustCompile(`^filter\\.(.*)\\.[^.]+$`)', 'filterNameRe = regexp.MustCompile(`^filter\\.([^.]*)\\.[^.]+$`)', R_VF)
m(VF, '"-c", "gpg.ssh.program=" + sshKeygen, "-c", "gpg.program=" + gpgBin,', '"-c", "gpg.program=" + gpgBin,', R_VF)
m(VF, '"-c", "gpg.ssh.program=" + sshKeygen, "-c", "gpg.program=" + gpgBin,', '"-c", "gpg.ssh.program=" + sshKeygen,', R_VF)
m(VF, '"-c", "gpg.x509.program=" + falseBin}', "}", R_VF)
m(VF, 'args = append(args, "-c", "gpg.format=ssh", "-c", "gpg.ssh.allowedSignersFile="+trustRoot)', 'args = append(args, "-c", "gpg.format=ssh")', R_VF)
m(VF, 'args = append(args, "-c", "gpg.format=openpgp", "-c", "gpg.ssh.allowedSignersFile=/dev/null")', 'args = append(args, "-c", "gpg.format=openpgp")', R_VF)
m(VF, 'if _, ok := vgit(realRepo, "merge-base", "--is-ancestor", t, "HEAD"); !ok {', "if false {", R_VF)
m(VF, 'if c.RequireCleanWorktree() == "true" {', "if false {", R_VF)
m(VF, "return a < b", "return a > b", R_VF)
m(VF, 'return rk[i].behind+"\\t"+rk[i].tag < rk[j].behind+"\\t"+rk[j].tag', "return rk[i].tag > rk[j].tag", R_VF)
m(VF, 'if root == "" {\n\t\t\t\tcontinue\n\t\t\t}', "break", R_VF)
m(VF, 'env = []string{"GNUPGHOME=" + emptyGnupg}', "env = []string{}", R_VF, equivalent="needs a real OpenPGP-signed tag and key to observe")
m(VF, 'if signer == "" {\n\t\t\t\t\tsigner = "unknown"\n\t\t\t\t}', "", R_VF, equivalent="a verifying tag always yields a principal in these fixtures")
m(VF, "for _, sub := range []string{\"clean\", \"smudge\", \"process\", \"required\"} {", "for _, sub := range []string{\"clean\", \"smudge\", \"required\"} {", R_VF)

GT = "internal/vetting/gate.go"
R_GT = "TestVettingGateGolden"
m(GT, 'overCommit := cap != "" && numCmp(behind, cap, "gt")', 'overCommit := cap != "" && numCmp(behind, cap, "gt") && false', R_GT)
m(GT, 'if cap != "" && !overAge {', 'if cap != "" {', R_GT)
m(GT, 'if acceptUnvetted == "true" || acceptDrift == "true" {\n\t\t\td.errln(fmt.Sprintf("  %s: attestation is', 'if acceptDrift == "true" {\n\t\t\td.errln(fmt.Sprintf("  %s: attestation is', R_GT)
m(GT, 'if acceptUnvetted == "true" {\n\t\t\td.errln(fmt.Sprintf("  %s: vetted but %s commit(s) behind HEAD — over cap', 'if acceptUnvetted == "true" || acceptDrift == "true" {\n\t\t\td.errln(fmt.Sprintf("  %s: vetted but %s commit(s) behind HEAD — over cap', R_GT)
m(GT, 'if acceptDrift != "true" {\n\t\t\t\tm = "flag:--i-accept-unvetted-repo"\n\t\t\t}\n\t\t\td.RecordOverride(m, fmt.Sprintf("stale', 'if acceptDrift == "true" {\n\t\t\t\tm = "flag:--i-accept-unvetted-repo"\n\t\t\t}\n\t\t\td.RecordOverride(m, fmt.Sprintf("stale', R_GT)
m(GT, 'if cfg.ForbidOverride == "true" {', 'if cfg.ForbidOverride != "false" {', R_GT)
m(GT, 'accept = "false"\n\t\t}', "", R_GT)
m(GT, 'if posture == "off" {', 'if posture == "off" || posture == "" {', R_GT)
m(GT, 'if posture == "required" {\n\t\t\td.errln("",\n\t\t\t\t"ERROR: vetting is required but no signer', 'if posture != "advisory" {\n\t\t\td.errln("",\n\t\t\t\t"ERROR: vetting is required but no signer', R_GT)
m(GT, 'if numCmp(f5, "0", "eq") && !overAge {', 'if numCmp(f5, "0", "eq") {', R_GT)
m(GT, 'if posture == "advisory" {\n\t\t\t\tswitch {', 'if posture != "required" {\n\t\t\t\tswitch {', R_GT)
m(GT, 'if accept != "true" && d.TTY {', "if d.TTY {", R_GT)
m(GT, 'if ((is == "unvetted" && strings.HasPrefix(if3, "no ")) || is == "drift") &&', 'if (is == "unvetted" || is == "drift") &&', R_GT)
m(GT, "d.SigningConfigured(ir) && d.InlineAttest(ir, if2) {", "d.InlineAttest(ir, if2) {", R_GT)
m(GT, "if len(remaining) == 0 {", "if len(remaining) == 0 && false {", R_GT)
m(GT, 'if bashcompat.ReadTab(e, 4)[1] == "drift" {', "if false {", R_GT)
m(GT, "if overrideForbidden {", "if false {", R_GT)
m(GT, "func yes(r string) bool { return len(r) > 0 && (r[0] == 'y' || r[0] == 'Y') }", "func yes(r string) bool { return len(r) > 0 && r[0] == 'y' }", R_GT)
m(GT, "if len(r) > 12 {", "if len(r) > 11 {", R_GT, equivalent="r[:12] of a 12-character string is unchanged")

EX = "internal/vetting/exceptions.go"
R_EX = "TestExceptionsGolden"
m(EX, "for _, name := range []string{ignoreName, ignoreFallback} {", "for _, name := range []string{ignoreFallback, ignoreName} {", R_EX)
m(EX, 'if rev == "" {', "if false {", R_EX)
m(EX, 'if c.statusFields(repo)[0] != "vetted" {', "if false {", R_EX)
m(EX, 'if honorFlag != "true" {', 'if honorFlag == "false" {', R_EX)
m(EX, 'if acceptUnvetted == "true" {\n\t\t\treturn LoadRepoIgnoreFingerprints(repo)', 'if acceptUnvetted != "false" {\n\t\t\treturn LoadRepoIgnoreFingerprints(repo)', R_EX)
m(EX, 'if c.ExceptionsRequireHead() == "true" {', "if false {", R_EX)
m(EX, 'return CommittedIgnoreFingerprints(repo, tag)', 'return CommittedIgnoreFingerprints(repo, "HEAD")', R_EX)
m(EX, 'if c.ExceptionsFromCommit() == "true" {', 'if c.ExceptionsFromCommit() != "false" {', R_EX, equivalent="the getter only returns true or false")
m(EX, 'for _, p := range []string{"ssh-", "sk-ssh-", "ecdsa-sha2-", "key::"} {', 'for _, p := range []string{"ssh-", "ecdsa-sha2-", "key::"} {', R_EX)
m(EX, 'return config.IsFile(c.tilde(key))', "return config.IsFile(key)", R_EX)
m(EX, 'if vsk := c.SigningKey(); vsk != "" {', "if vsk := c.SigningKey(); false {", R_EX)
m(EX, 'if c.TrustFormat() == "gpg" {\n\t\treturn true', "if false {\n\t\treturn true", R_EX)
m(EX, 'return "mismatch"', 'return "unconfigured"', R_EX)

AT = "internal/vetting/attest.go"
R_AT = "TestAttestGolden"
m(AT, 'if msg == "" {\n\t\tmsg = "vetted for agent use"\n\t}', 'if false {\n\t\tmsg = "vetted for agent use"\n\t}', R_AT)
m(AT, 'if a.RequireCleanWorktree() == "true" {\n\t\tif st', "if false {\n\t\tif st", R_AT)
m(AT, 'if _, ok := vgit(real, "rev-parse", "-q", "--verify", "refs/tags/"+tag); ok {', "if false {", R_AT)
m(AT, "if !a.AcknowledgeExceptions(real, repo, assumeYes) {", "if false {", R_AT)
m(AT, '"-c", "gpg.x509.program=" + falseBin, "-c", "gpg.ssh.defaultKeyCommand="}', '"-c", "gpg.x509.program=" + falseBin}', R_AT)
m(AT, 'opts := []string{"-c", "gpg.ssh.program=" + sshKeygen, "-c", "gpg.program=" + gpgBin,', 'opts := []string{"-c", "gpg.program=" + gpgBin,', R_AT)
m(AT, 'opts = append(opts, "-c", "gpg.format=ssh", "-c", "user.signingkey="+vsk)', 'opts = append(opts, "-c", "user.signingkey="+vsk)', R_AT)
m(AT, 'opts = append(opts, "-c", "gpg.format=ssh")', 'opts = append(opts, "-c", "gpg.format=openpgp")', R_AT)
m(AT, '} else if fmtName == "ssh" && state == "mismatch" {', '} else if state == "mismatch" {', R_AT)
m(AT, "if len(accepted) == 0 {\n\t\treturn true\n\t}", "if false {\n\t\treturn true\n\t}", R_AT)
m(AT, 'if f[0] != "accepted" {', 'if f[0] == "no" {', R_AT)
m(AT, 'if assumeYes == "true" {\n\t\ta.errln("  Acknowledged via --yes.")', 'if assumeYes != "false" {\n\t\ta.errln("  Acknowledged via --yes.")', R_AT)
m(AT, 'if !a.TTYIn {\n\t\ta.errln("ERROR: not an interactive terminal', 'if false {\n\t\ta.errln("ERROR: not an interactive terminal', R_AT)
m(AT, 'if commandV("betterleaks") == "" || commandV("jq") == "" {', 'if commandV("betterleaks") == "" {', R_AT, equivalent="needs a PATH without jq")
m(AT, 'if f[0] == "vetted" {\n\t\ta.errln(fmt.Sprintf("  ✓', 'if f[0] != "" {\n\t\ta.errln(fmt.Sprintf("  ✓', R_AT)
m(AT, 'vgit(real, "tag", "-d", a.TagPrefix+headSha)', "_ = real", R_AT)
m(AT, 'if a.AttestRepo(repo, "vetted for agent use (attested at launch)", "false") != 0 {', 'if a.AttestRepo(repo, "vetted for agent use (attested at launch)", "true") != 0 {', R_AT)
m(AT, 'if a.TrustFormat() == "gpg" {\n\t\treturn 0\n\t}', "if false {\n\t\treturn 0\n\t}", R_AT)
m(AT, "if !a.TTYBoth {\n\t\treturn 0\n\t}", "if false {\n\t\treturn 0\n\t}", R_AT)
m(AT, 'gitGlobalConfig("gpg.format", "ssh")', "_ = 0", R_AT)
m(AT, 'UpsertYAMLScalar(a.UserConfig, "vetting_signing_key", pick)', "_ = pick", R_AT)
m(AT, 'if email != "" && keyline != "" {', 'if email != "" {', R_AT)
m("internal/config/config.go", 'if !done && strings.HasPrefix(line, key+":") {', 'if strings.HasPrefix(line, key+":") {', R_AT, pkg="vetting")
