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

CW = "internal/config/write.go"
CR = "internal/config/repo.go"
R_CW = "TestWriteGolden"
m(CW, "return len(data) > 0 && data[len(data)-1] != '\\n' && data[len(data)-1] != 0", "return len(data) > 0 && data[len(data)-1] != '\\n'", R_CW, pkg="config")
m(CW, "\tif !strings.HasPrefix(l, key+\":\") {\n\t\t\tkeep = append(keep, l)", "\tif !strings.HasPrefix(l, key) {\n\t\t\tkeep = append(keep, l)", R_CW, pkg="config")
m(CW, "\treturn os.Chmod(path, 0o600)\n}", "\treturn nil\n}", R_CW, pkg="config")
m(CW, "\t\tif existing == relpath {\n\t\t\treturn nil", "\t\tif false {\n\t\t\treturn nil", R_CW, pkg="config")
m(CW, 'return os.WriteFile(configFile, []byte("masked_paths:\\n"+item+"\\n"), 0o666)', 'return os.WriteFile(configFile, []byte("masked_paths:\\n"+item+"\\n"), 0o600)', R_CW, pkg="config")
m(CW, "\t\tif endsWithoutNewline(data) {\n\t\t\tadd = append(add, '\\n')\n\t\t}\n\t\tadd = append(add, \"masked_paths:", "\t\tadd = append(add, \"masked_paths:", R_CW, pkg="config")
m(CW, "\t\tins = awkUnescape(item)", "\t\tins = item", R_CW, pkg="config")
m(CW, "\t\tif !done && strings.HasPrefix(l, \"masked_paths:\") {\n\t\t\tout = append(out, ins)", "\t\tif strings.HasPrefix(l, \"masked_paths:\") {\n\t\t\tout = append(out, ins)", R_CW, pkg="config")
m(CW, "\t\tcase 'n':\n\t\t\tb.WriteByte('\\n')", "\t\tcase 'n':\n\t\t\tb.WriteByte('n')", R_CW, pkg="config")
m(CW, "\t\tcase '\\\\', '\"', '/':", "\t\tcase '\\\\', '/':", R_CW, pkg="config")
m(CW, "\t\tcase 't':\n\t\t\tb.WriteByte('\\t')", "\t\tcase 't':\n\t\t\tb.WriteByte('t')", R_CW, pkg="config")
m(CW, "for n < 3 && i < len(s)", "for n < 2 && i < len(s)", R_CW, pkg="config")
m(CW, "\t\t\tif existing == fingerprint {\n\t\t\t\treturn nil", "\t\t\tif false {\n\t\t\t\treturn nil", R_CW, pkg="config")
m(CW, '\t\tr := strings.NewReplacer("\\r", "", "\\n", "", "\\x00", "").Replace(reason)', "\t\tr := reason", R_CW, pkg="config")
m(CW, '\t\tr = strings.TrimPrefix(r, "#")\n', "", R_CW, pkg="config")
m(CW, '\t\tr = strings.TrimPrefix(r, " ")\n', "", R_CW, pkg="config")
m(CW, "\t\tif endsWithoutNewline(data) {\n\t\t\tadd = append(add, '\\n')\n\t\t}\n\t}\n\tif reason", "\t}\n\tif reason", R_CW, pkg="config")
m(CW, "\tif !found {\n\t\treturn nil\n\t}", "", R_CW, pkg="config")
m(CW, "\t\tcase inblock && indentedDashOrHash(l):", "\t\tcase false:", R_CW, pkg="config")
m(CW, "\t\tcase inblock && isBlank(l):", "\t\tcase false:", R_CW, pkg="config")
m(CW, "\t\tinblock = false\n\t\tout = append(out, l)", "\t\tout = append(out, l)", R_CW, pkg="config")
m(CW, "return i > 0 && i < len(l) && (l[i] == '-' || l[i] == '#')", "return i < len(l) && (l[i] == '-' || l[i] == '#')", R_CW, pkg="config")
m(CW, "return i > 0 && i < len(l) && (l[i] == '-' || l[i] == '#')", "return i > 0 && i < len(l) && l[i] == '-'", R_CW, pkg="config")
m(CR, "\tfor _, f := range []string{RepoIgnoreName, RepoIgnoreFallback} {\n\t\tif IsFile(", "\tfor _, f := range []string{RepoIgnoreName, RepoIgnoreFallback} {\n\t\tif Exists(", R_CW, pkg="config")
m(CR, "\tfor _, f := range []string{RepoIgnoreName, RepoIgnoreFallback} {\n\t\tif IsFile(", "\tfor _, f := range []string{RepoIgnoreFallback, RepoIgnoreName} {\n\t\tif IsFile(", R_CW, pkg="config")
m(CR, 'return ExtractYAMLScalar(ov+"/config.yaml", "honor_repo_allowed_domains") == "true"', 'return ExtractYAMLScalar(ov+"/config.yaml", "honor_repo_allowed_domains") != ""', R_CW, pkg="config")
m(CR, 'if ov == "" || !IsFile(ov+"/config.yaml") {', 'if ov == "" {', R_CW, pkg="config",
  equivalent="ExtractYAMLScalar returns empty for a missing file too")
m(CR, "\tif strings.HasSuffix(s, string(sep)) {\n\t\tf = f[:len(f)-1]\n\t}", "", R_CW, pkg="config",
  equivalent="the dropped field is empty, and empty entries are skipped")
m(CR, "\t\tif n[0] == '.' && w[0] != '.' {\n\t\t\tcontinue\n\t\t}", "", R_CW, pkg="config")
m(CR, "\tsort.Strings(m)\n", "\t_ = sort.Strings\n", R_CW, pkg="config",
  equivalent="os.ReadDir already returns names sorted")
m(CR, "if d != \"\" && !echoOption.MatchString(d) {", "if d != \"\" {", R_CW, pkg="config")
m(CR, "if r < 0x80 && isSpace(byte(r)) {", "if r == ' ' {", R_CW, pkg="config")
m(CR, 'if !strings.ContainsAny(w, "*?[") || strings.Contains(w, "/") {', 'if !strings.ContainsAny(w, "*?") || strings.Contains(w, "/") {', R_CW, pkg="config")

PF = "internal/config/profile.go"
R_PF = "TestProfileGolden"
m(PF, 'func IsNumericProfile(name string) bool { return name == "1" || name == "2" || name == "3" }', 'func IsNumericProfile(name string) bool { return name == "1" || name == "2" }', R_PF, pkg="config")
m(PF, '!strings.Contains(name, "..") && !strings.HasPrefix(name, ".")', '!strings.HasPrefix(name, ".")', R_PF, pkg="config")
m(PF, 'name != "" && !IsNumericProfile(name) &&', 'name != "" &&', R_PF, pkg="config")
m(PF, "profileNameChars = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)", "profileNameChars = regexp.MustCompile(`^[A-Za-z0-9._ -]+$`)", R_PF, pkg="config")
m(PF, 'if p := UserProfilesDir(e) + "/" + name + ".yaml"; IsFile(p) {', 'if p := UserProfilesDir(e) + "/" + name + ".yaml"; Exists(p) {', R_PF, pkg="config")
m(PF, 'if p := ov + "/profiles/" + name + ".yaml"; IsFile(p) {', 'if p := ov + "/profiles/" + name + ".yaml"; Exists(p) {', R_PF, pkg="config")
m(PF, 'if p := ov + "/blocked-destinations.yaml"; IsFile(p) {', 'if p := ov + "/blocked-destinations.yaml"; Exists(p) {', R_PF, pkg="config")
m(PF, "minVersionForm = regexp.MustCompile(`^v?[0-9]+(\\.[0-9]+)*$`)", "minVersionForm = regexp.MustCompile(`^v?[0-9]+(\\.[0-9]*)*$`)", R_PF, pkg="config")
m(PF, 'if version == "" || version == "dev" {', 'if version == "dev" {', R_PF, pkg="config")
m(PF, "\tif VersionGE(version, min) {\n\t\treturn \"\", nil\n\t}", "\tif VersionGE(min, version) {\n\t\treturn \"\", nil\n\t}", R_PF, pkg="config")
m(PF, 'fa, fb := versionFields(strings.TrimPrefix(a, "v")), versionFields(strings.TrimPrefix(b, "v"))', 'fa, fb := versionFields(a), versionFields(b)', R_PF, pkg="config")
m(PF, "\tif strings.HasSuffix(v, \".\") {\n\t\tf = f[:len(f)-1]\n\t}", "", R_PF, pkg="config",
  equivalent="a trailing empty field reads as 0, the same as a missing one")
m(PF, "\tif i == 0 {\n\t\treturn \"0\"\n\t}", "", R_PF, pkg="config",
  equivalent="an empty field makes bashArith 0, the same as \"0\"")
m(PF, "\t\tv = v*10 + uint64(d[i]-'0')", "\t\tv = v*10 + uint64(d[i]-'0')\n\t\tif v > 1<<62 {\n\t\t\tv = 1 << 62\n\t\t}", R_PF, pkg="config")
m(PF, "\tcase ia > ib:\n\t\treturn 1", "\tcase ia >= ib:\n\t\treturn 1", R_PF, pkg="config")
m(PF, '\tif agent != "" {\n\t\tfmt.Fprintf(&b, "agent: %s\\n", agent)', '\tif true {\n\t\tfmt.Fprintf(&b, "agent: %s\\n", agent)', R_PF, pkg="config")
m(PF, "\t\tif d != \"\" {\n\t\t\tds = append(ds, d)", "\t\tif true {\n\t\t\tds = append(ds, d)", R_PF, pkg="config")
m(PF, "\tif len(ds) > 0 {\n\t\tb.WriteString(\"extra_allowed_domains:\\n\")", "\tif true {\n\t\tb.WriteString(\"extra_allowed_domains:\\n\")", R_PF, pkg="config")

CK = "internal/checks/checks.go"
R_CK = "TestChecksGolden"
m(CK, "\td = strings.TrimRight(d, \"\\n\")\n\td = strings.TrimRight(d, \".\")", "\td = strings.TrimRight(d, \".\")", R_CK)
m(CK, "\td = strings.TrimRight(d, \".\")\n\treturn strings.TrimRight(d, \"\\n\")", "\treturn strings.TrimRight(d, \"\\n\")", R_CK)
m(CK, "\t\tif r >= 'A' && r <= 'Z' {", "\t\tif r >= 'A' && r < 'Z' {", R_CK)
m(CK, "return domain == apex || strings.HasSuffix(domain, \".\"+apex)", "return strings.HasSuffix(domain, \".\"+apex)", R_CK)
m(CK, "return domain == apex || strings.HasSuffix(domain, \".\"+apex)", "return domain == apex || strings.HasSuffix(domain, apex)", R_CK)
m(CK, "\t\treturn strings.HasSuffix(domain, p[1:])", "\t\treturn strings.HasPrefix(domain, p[1:])", R_CK)
m(CK, "return domain == prefix || strings.HasPrefix(domain, prefix+\".\")", "return strings.HasPrefix(domain, prefix+\".\")", R_CK)
m(CK, "return domain == prefix || strings.HasPrefix(domain, prefix+\".\")", "return domain == prefix || strings.HasPrefix(domain, prefix)", R_CK)
m(CK, "\tp := NormalizeDomain(pattern)", "\tp := pattern", R_CK)
m(CK, "\tif ov := config.OverlayBlockedDestinationsFile(c.Env); ov != \"\" {\n\t\tf = append(f, [2]string{ov, \"overlay\"})\n\t}", "", R_CK)
m(CK, "\tif config.IsFile(c.UserConfig) {\n\t\tf = append(f, [2]string{c.UserConfig, \"user\"})\n\t}", "", R_CK)
m(CK, "\t\treturn []string{\"WARN: blocked-destinations.yaml not found; skipping block check.\"}, nil", "\t\treturn nil, nil", R_CK)
m(CK, "\tif !config.IsFile(c.OrgFile) {\n\t\tif deviation", "\tif false {\n\t\tif deviation", R_CK)
m(CK, "\t\t\tif strings.TrimSpace(x) != \"\" && !seen[x] { // awk", "\t\t\tif strings.TrimSpace(x) != \"\" { // awk", R_CK)
m(CK, "legacyIPv4CIDR = regexp.MustCompile(`^([0-9]{1,3}\\.){3}[0-9]{1,3}/[0-9]{1,2}$`)", "legacyIPv4CIDR = regexp.MustCompile(`^([0-9]{1,3}\\.){3}[0-9]{1,3}/[0-9]{1,3}$`)", R_CK)
m(CK, "(strings.Contains(cidr, \":\") && legacyIPv6CIDR.MatchString(cidr))", "legacyIPv6CIDR.MatchString(cidr)", R_CK)
m(CK, "ipv4Shape      = regexp.MustCompile(`^([0-9]{1,3}\\.){3}[0-9]{1,3}$`)", "ipv4Shape      = regexp.MustCompile(`^([0-9]{1,3}\\.){3}[0-9]{1,4}$`)", R_CK)
m(CK, "\t} else if strings.HasSuffix(ip, \".\") {\n\t\tf = f[:len(f)-1]\n\t}", "\t}", R_CK)
m(CK, "\t\tif !ok || v < 0 || v > 255 {", "\t\tif !ok || v < 0 || v > 256 {", R_CK)
m(CK, "\tif len(d) > 1 && d[0] == '0' {", "\tif false {", R_CK)
m(CK, "\t\t\tif d[i] > '7' {\n\t\t\t\treturn 0, false", "\t\t\tif d[i] > '9' {\n\t\t\t\treturn 0, false", R_CK)
m(CK, "\tnetPart := cidr[:strings.LastIndex(cidr, \"/\")]", "\tnetPart := cidr[:strings.Index(cidr, \"/\")]", R_CK,
  equivalent="with two '/' the prefix part contains a '/' and is rejected whichever '/' ends the network part")
m(CK, "\tif !ok || prefix < 0 || prefix > 32 {", "\tif !ok || prefix < 0 || prefix > 33 {", R_CK)
m(CK, "\tif prefix != 0 {\n\t\tmask = uint32(0xFFFFFFFF << (32 - prefix))\n\t}", "\tmask = uint32(0xFFFFFFFF << (32 - prefix))", R_CK,
  equivalent="a shift by 32 of a 64-bit constant leaves 0 in the low 32 bits, the same mask")
m(CK, "\t\tif strings.Contains(x, \":\") {\n\t\t\tcontinue\n\t\t}\n\t\tif IPInCIDR", "\t\tif IPInCIDR", R_CK,
  equivalent="IPInCIDR already returns false for any input containing ':'")
m(CK, "\tif strings.Contains(ip, \":\") {\n\t\treturn []string{", "\tif false {\n\t\treturn []string{", R_CK)
m(CK, "\t\tco.uk org.uk me.uk", "\t\torg.uk me.uk", R_CK)
m(CK, "s3.amazonaws.com cloudfront.net", "cloudfront.net", R_CK)
m(CK, "\tif !strings.Contains(name, \".\") || IsMultilabelPublicSuffix(name) {", "\tif !strings.Contains(name, \".\") {", R_CK)
m(CK, "\t\treturn IsMultilabelPublicSuffix(rest)\n\t}\n\treturn true", "\t\treturn false\n\t}\n\treturn true", R_CK)
m(CK, "\tif !strings.HasPrefix(d, \"*.\") {\n\t\treturn true", "\tif !strings.HasPrefix(d, \"*\") {\n\t\treturn true", R_CK)
m(CK, "\tcase strings.Contains(rest, \"*\"),", "\tcase false,", R_CK)
m(CK, "\t\tstrings.HasPrefix(rest, \".\"), strings.HasSuffix(rest, \".\"), strings.Contains(rest, \"..\"),", "\t\tstrings.HasPrefix(rest, \".\"),", R_CK)
m(CK, "\t\t!strings.Contains(rest, \".\"):", "\t\tfalse:", R_CK)
m(CK, "\treturn IsMultilabelPublicSuffix(rest)\n}", "\treturn false\n}", R_CK)
m(CK, "\tif IsIPv4Literal(ipTarget) {", "\tif false {", R_CK)
m(CK, "\t\tif e == host {\n\t\t\treturn true", "\t\tif strings.EqualFold(e, host) {\n\t\t\treturn true", R_CK)
m(CK, "\tif ov == \"\" || !config.IsFile(ov+\"/config.yaml\") {\n\t\treturn false\n\t}\n\tfor _, e", "\tif ov == \"\" {\n\t\treturn false\n\t}\n\tfor _, e", R_CK,
  equivalent="ExtractYAMLList returns nothing for a missing file")

TR = "internal/tier/tier.go"
R_TR = "TestTierGolden"
m(TR, '\tcase "1", "2", "3":\n\t\treturn nil', '\tcase "1", "2":\n\t\treturn nil', R_TR)
m(TR, '\t"raw.githubusercontent.com",\n', "", R_TR)
m(TR, 'if tier == "2" || tier == "3" {', 'if tier == "2" {', R_TR)
m(TR, "\tif tier == \"3\" {\n\t\treturn 180", "\tif tier == \"2\" {\n\t\treturn 180", R_TR)
m(TR, '\t\treturn "Infra"', '\t\treturn "Infra "', R_TR)
m(TR, "Valid tiers: 1, 2, 3.\\n \", tier)", "Valid tiers: 1, 2, 3.\", tier)", R_TR)

CT = "internal/catalogue/catalogue.go"
R_CT = "TestCatalogueGolden"
m(CT, '!strings.Contains(name, "/") && !strings.Contains(name, "..") &&', '!strings.Contains(name, "/") &&', R_CT)
m(CT, 'if p := c.OrgDir() + "/" + name + ".yaml"; config.IsFile(p) {', 'if p := c.OrgDir() + "/" + name + ".yaml"; false {', R_CT)
m(CT, '\tif st, err := os.Stat(ov + "/catalogue"); err == nil && st.IsDir() {', '\tif true {', R_CT,
  equivalent="without the overlay's catalogue directory no entry file can exist inside it, so Resolve misses either way")
m(CT, "\tif !deviation.Fixed(deviation.EchoOptionItems) && echoOption.MatchString(v) {\n\t\treturn \"\"", "\tif false {\n\t\treturn \"\"", R_CT)
m(CT, "\tif v == \"\" {\n\t\tv = def\n\t}", "", R_CT)
m(CT, 'if kind != "mcp" && kind != "service" {', 'if kind != "mcp" && kind != "service" && kind != "MCP" {', R_CT)
m(CT, "digestPinned = regexp.MustCompile(`@sha256:[0-9a-f]{64}$`)", "digestPinned = regexp.MustCompile(`@sha256:[0-9a-fA-F]{64}$`)", R_CT)
m(CT, "digestPinned = regexp.MustCompile(`@sha256:[0-9a-f]{64}$`)", "digestPinned = regexp.MustCompile(`@sha256:[0-9a-f]{64}`)", R_CT)
m(CT, "if v, ok := intOf(port); ok && (v < 1 || v > 65535) {", "if v, ok := intOf(port); ok && (v < 1 || v > 65536) {", R_CT)
m(CT, "if v, ok := intOf(port); ok && (v < 1 || v > 65535) {", "if v, ok := intOf(port); !ok || (v < 1 || v > 65535) {", R_CT)
m(CT, "\t\t\tif v, ok := intOf(uid); ok && v == 0 {", "\t\t\tif v, ok := intOf(uid); !ok || v == 0 {", R_CT)
m(CT, '\t\tif d == "*" {\n\t\t\treturn fail(pre + "egress', '\t\tif false {\n\t\t\treturn fail(pre + "egress', R_CT)
m(CT, "\t\tif _, err := c.CheckDomainNotBlocked(d); err != nil {", "\t\tif false {", R_CT)
m(CT, '\t\tif s != "" && !secretName.MatchString(s) {', '\t\tif false {', R_CT)
m(CT, "secretName   = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)", "secretName   = regexp.MustCompile(`^[A-Z0-9_]+$`)", R_CT)
m(CT, '\tif kind == "mcp" {\n\t\tif t := Field', '\tif true {\n\t\tif t := Field', R_CT)
m(CT, 'if t := Field(path, "mcp_transport", "http"); t != "http" && t != "sse" {', 'if t := Field(path, "mcp_transport", "http"); t != "http" {', R_CT)
m(CT, '"cap_add", "capabilities", "privileged", "host_network", "hostPID", "hostIPC"}', '"cap_add", "capabilities", "host_network", "hostPID", "hostIPC"}', R_CT)
m(CT, '\t\tif strings.HasPrefix(l, key+":") {\n\t\t\treturn true', '\t\tif strings.HasPrefix(strings.TrimSpace(l), key+":") {\n\t\t\treturn true', R_CT)
m(CT, '\t\tif strings.HasPrefix(l, key+":") {\n\t\t\treturn true', '\t\tif strings.HasPrefix(l, key) {\n\t\t\treturn true', R_CT)
m(CT, 'if class == "browser" && verify != "true" {', 'if class == "browser" && verify == "" {', R_CT)
m(CT, '\tif verify == "true" {\n\t\treturn c.VerifyImageSignature', '\tif verify != "" {\n\t\treturn c.VerifyImageSignature', R_CT)
m(CT, "\tif !c.HasCosign() {", "\tif false {", R_CT)
m(CT, '\tcase key != "":\n\t\targs = append(args, "--key", key)', '\tcase key != "":\n\t\targs = append(args, "--key")', R_CT)
m(CT, '\tcase identity != "" && issuer != "":', '\tcase identity != "":', R_CT)
m(CT, "\tif !c.RunCosign(append(args, image)) {", "\tif !c.RunCosign(args) {", R_CT)
