"""Planted bugs for tools/mutate.py. One entry = one exact replacement in one file.

file: path under go/; pkg: the package whose tests run; run: the go test -run pattern;
equivalent: a reason string when the bug cannot change observable behaviour (a survivor that is
not marked equivalent means the corpus has a gap)."""

MUTANTS = []


def m(file, old, new, run, equivalent=None, pkg=None):
    # pkg: the package whose tests run; for shared packages (config, bashcompat) it is the package
    # whose corpus exercises the code, so it must be given (default: the file's own package)
    if pkg is None:
        parts = file.split("/")
        if file.startswith("internal/host/"):
            pkg = "host/" + parts[2]  # the host binary's packages are one level deeper
        else:
            pkg = PKG_OVERRIDE.get(file) or (parts[1] if file.startswith("internal/") else "")
    MUTANTS.append(dict(file=file, old=old, new=new, run=run, pkg=pkg, equivalent=equivalent))


PKG_OVERRIDE = {
    "internal/config/config.go": "gate",
    "internal/bashcompat/bashcompat.go": "gate",
    "internal/jqjson/jqjson.go": "audit",
    "internal/secrets/secrets.go": "cli",
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
m(ENC, "if !f.ok || !digitsOnly.MatchString(line) {", "if !f.ok {", R_ENC)
m(ENC, "if !f.ok || !digitsOnly.MatchString(line) {", "if !digitsOnly.MatchString(line) {", R_ENC,
  equivalent="a file that could not be read has no lines and no SealedSecret kind line, so nothing matches")
m(ENC, "if n < 1 || n > float64(len(lines)) || n != float64(int(n)) {", "if n < 1 || n > float64(len(lines)) {", R_ENC,
  equivalent="n comes from a digits-only line number, so it is always whole")
m(ENC, "\t\t\t\t\t\tf.sealed = true\n", "", R_ENC)
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
m("internal/tables/tables.go", '".env", ".env.local", ".npmrc"', '".env", ".npmrc"', R_MSK, pkg="gate")
m(MSK, "relpath == MaskedDirPath ||", "false ||", R_MSK)
m(MSK, 'MaskedDirPath+"/")', "MaskedDirPath)", R_MSK)
m(MSK, '!strings.Contains(relpath, "/") &&', "", R_MSK)
m(MSK, "strings.HasSuffix(relpath, maskedOpenrcSuffix)", 'strings.HasSuffix(relpath, "openrc.sh")', R_MSK)
m(MSK, 'if relpath == d || strings.HasPrefix(relpath, d+"/") {', 'if strings.HasPrefix(relpath, d+"/") {', R_MSK)
m(MSK, 'if relpath == d || strings.HasPrefix(relpath, d+"/") {', "if relpath == d || strings.HasPrefix(relpath, d) {", R_MSK)

CFG = "internal/config/config.go"
R_CFG = "TestListsGolden|TestMaskedGolden"
YL = "internal/yamllist/yamllist.go"  # the list reader, shared with the host sync gate; its corpus is config's
m(YL, 'if strings.HasPrefix(line, key+":") {\n\t\t\tflag = true', "if strings.HasPrefix(line, key) {\n\t\t\tflag = true", R_CFG, pkg="gate")
m(YL, "(c >= 'A' && c <= 'Z') || ", "", R_CFG, pkg="gate")
m(YL, "c == '_' || ", "", R_CFG, pkg="gate")
m(YL, "if legacyEcho && echoOption.MatchString(line) {", "if false {", R_CFG, pkg="gate")
m(YL, "if legacyEcho && echoOption.MatchString(item) {", "if false {", R_CFG, pkg="gate")
m(YL, "if isSpace(item[i]) && item[i+1] == '#' {", "if item[i] == ' ' && item[i+1] == '#' {", R_CFG, pkg="gate")
m(YL, 'item = strings.TrimRight(item, " \\t\\n\\v\\f\\r")', 'item = strings.TrimRight(item, " ")', R_CFG, pkg="gate")
m(YL, 'item = strings.NewReplacer(`"`, "", `\'`, "").Replace(item)', 'item = strings.NewReplacer(`"`, "").Replace(item)', R_CFG, pkg="gate")
m(YL, "if item == \"\" || item[0] == '#' {", 'if item == "" {', R_CFG, pkg="gate")
m(YL, "flag = true\n\t\t\tcontinue", "flag = true", R_CFG, pkg="gate")
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
m(SC, "[]string{config.RepoIgnoreName, config.RepoIgnoreFallback}", "[]string{repoIgnoreName}", R_SCAN)
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
m(GT, 'overCommit := cap != "" && NumCmp(behind, cap, "gt")', 'overCommit := cap != "" && NumCmp(behind, cap, "gt") && false', R_GT)
m(GT, 'if cap != "" && !overAge {', 'if cap != "" {', R_GT)
m(GT, 'if acceptUnvetted == "true" || acceptDrift == "true" {\n\t\t\td.errln(fmt.Sprintf("  %s: attestation is', 'if acceptDrift == "true" {\n\t\t\td.errln(fmt.Sprintf("  %s: attestation is', R_GT)
m(GT, 'if acceptUnvetted == "true" {\n\t\t\td.errln(fmt.Sprintf("  %s: vetted but %s commit(s) behind HEAD — over cap', 'if acceptUnvetted == "true" || acceptDrift == "true" {\n\t\t\td.errln(fmt.Sprintf("  %s: vetted but %s commit(s) behind HEAD — over cap', R_GT)
m(GT, 'if acceptDrift != "true" {\n\t\t\t\tm = "flag:--i-accept-unvetted-repo"\n\t\t\t}\n\t\t\td.RecordOverride(m, fmt.Sprintf("stale', 'if acceptDrift == "true" {\n\t\t\t\tm = "flag:--i-accept-unvetted-repo"\n\t\t\t}\n\t\t\td.RecordOverride(m, fmt.Sprintf("stale', R_GT)
m(GT, 'if cfg.ForbidOverride == "true" {', 'if cfg.ForbidOverride != "false" {', R_GT)
m(GT, 'accept = "false"\n\t\t}', "", R_GT)
m(GT, 'if posture == "off" {', 'if posture == "off" || posture == "" {', R_GT)
m(GT, 'if posture == "required" {\n\t\t\td.errln("",\n\t\t\t\t"ERROR: vetting is required but no signer', 'if posture != "advisory" {\n\t\t\td.errln("",\n\t\t\t\t"ERROR: vetting is required but no signer', R_GT)
m(GT, 'if NumCmp(f5, "0", "eq") && !overAge {', 'if NumCmp(f5, "0", "eq") {', R_GT)
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
m(EX, "for _, name := range []string{config.RepoIgnoreName, config.RepoIgnoreFallback} {", "for _, name := range []string{ignoreFallback, ignoreName} {", R_EX)
m(EX, 'if rev == "" {', "if false {", R_EX)
m(EX, 'if c.statusFields(repo)[0] != "vetted" {', "if false {", R_EX)
m(EX, 'if honorFlag != "true" {', 'if honorFlag == "false" {', R_EX)
m(EX, 'if acceptUnvetted == "true" {\n\t\t\treturn config.LoadRepoIgnoreFingerprints(repo)', 'if acceptUnvetted != "false" {\n\t\t\treturn config.LoadRepoIgnoreFingerprints(repo)', R_EX)
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
# domain normalization and block patterns moved to egressmatch; checks' goldens still cover them
EM = "internal/egressmatch/egressmatch.go"
m(EM, "\td = strings.TrimRight(d, \"\\n\")\n\td = strings.TrimRight(d, \".\")", "\td = strings.TrimRight(d, \".\")", R_CK, pkg="checks")
m(EM, "\td = strings.TrimRight(d, \".\")\n\treturn strings.TrimRight(d, \"\\n\")", "\treturn strings.TrimRight(d, \"\\n\")", R_CK, pkg="checks")
m(EM, "\t\tif r >= 'A' && r <= 'Z' {", "\t\tif r >= 'A' && r < 'Z' {", R_CK, pkg="checks")
m(EM, "return domain == apex || strings.HasSuffix(domain, \".\"+apex)", "return strings.HasSuffix(domain, \".\"+apex)", R_CK, pkg="checks")
m(EM, "return domain == apex || strings.HasSuffix(domain, \".\"+apex)", "return domain == apex || strings.HasSuffix(domain, apex)", R_CK, pkg="checks")
m(EM, "\t\treturn strings.HasSuffix(domain, p[1:])", "\t\treturn strings.HasPrefix(domain, p[1:])", R_CK, pkg="checks")
m(EM, "return domain == prefix || strings.HasPrefix(domain, prefix+\".\")", "return strings.HasPrefix(domain, prefix+\".\")", R_CK, pkg="checks")
m(EM, "return domain == prefix || strings.HasPrefix(domain, prefix+\".\")", "return domain == prefix || strings.HasPrefix(domain, prefix)", R_CK, pkg="checks")
m(EM, "\tp := Normalize(pattern)", "\tp := pattern", R_CK, pkg="checks")
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

AU = "internal/audit/audit.go"
AJ = "internal/jqjson/jqjson.go"
R_AU = "TestAuditGolden"
m(AU, '\t\tif r != "" {\n\t\t\to.Repos = append(o.Repos, bashcompat.Basename(r))', '\t\tif true {\n\t\t\to.Repos = append(o.Repos, bashcompat.Basename(r))', R_AU)
m(AU, "o.Repos = append(o.Repos, bashcompat.Basename(r))", "o.Repos = append(o.Repos, r)", R_AU)
m(AU, "\tif err := os.WriteFile(tmp, []byte(out.String()), 0o600); err != nil {", "\tif err := os.WriteFile(tmp, []byte(out.String()), 0o644); err != nil {", R_AU,
  equivalent="the Chmod that follows sets 0600 either way")
m(AU, "\tos.Chmod(tmp, 0o600)\n", "", R_AU, equivalent="WriteFile already created the temp file 0600 (umask 022 cannot widen it)")
m(AU, "\t\tnv, err := f(v)\n\t\tif err != nil {\n\t\t\treturn\n\t\t}", "\t\tnv, _ := f(v)", R_AU)
m(AU, "\tcase Null:\n\t\tev = Arr(e)", "\tcase Null:\n\t\treturn v, fmt.Errorf(\"x\")", R_AU)
m(AU, "\tif v.Kind != Object && v.Kind != Null {\n\t\treturn v, fmt.Errorf(\"cannot index %s\", KindName(v.Kind))\n\t}\n\tev :=", "\tev :=", R_AU,
  equivalent="Set refuses a non-object anyway, with the same effect (the record is left unchanged)")
m(AU, 'ev := o.value().Merge(mustObj("time", Str(now), "type", Str("override")))', 'ev := mustObj("time", Str(now), "type", Str("override")).Merge(o.value())', R_AU)
m(AU, "\tif len(overrides) == 0 {\n\t\treturn\n\t}", "", R_AU, equivalent="the loop does nothing for no overrides")
m(AU, '\t\t\traw += `"` + d + `"`', '\t\t\traw += strconv.Quote(d)', R_AU)
m(AU, "\t\t\tos.WriteFile(p, nil, 0o666)\n\t\t\treturn line, err\n\t\t}\n\t}\n\ttierV", "\t\t\treturn line, err\n\t\t}\n\t}\n\ttierV", R_AU)
m(AU, '"infra_token", BoolV(s.InfraToken),', '"infra_token", BoolV(s.InfraKubeconfig),', R_AU)
m(AU, '\t\treturn Int(tier.RetentionDays(s.Tier))', '\t\treturn Int(90)', R_AU)
m(AU, '\tif reason == "" {\n\t\treturn\n\t}', "", R_AU)
m(AU, '\t\treturn v.Set("end_detail", Str(detail))', '\t\treturn v, nil', R_AU)
m(AU, "\t\tif deps.Kind != Array {\n\t\t\treturn v, nil\n\t\t}", "\t\tif deps.Kind == Null {\n\t\t\treturn v, nil\n\t\t}", R_AU)
m(AU, "\t\t\tnd, err := d.Set(\"down_time\", Str(downTime))\n\t\t\tif err != nil {\n\t\t\t\treturn v, err\n\t\t\t}", "\t\t\tnd, _ := d.Set(\"down_time\", Str(downTime))", R_AU)
m(AU, '\tev := mustObj("time", Str(now), "type", Str(eventType), "message", Str(message))', '\tev := mustObj("time", Str(now), "message", Str(message), "type", Str(eventType))', R_AU)
m(AU, '\t\tif !strings.HasPrefix(n, "ses-") {', '\t\tif !strings.HasPrefix(n, "ses") {', R_AU)
m(AU, "\t\tif st, err := os.Stat(filepath.Join(logDir, n)); err == nil && st.IsDir() {", "\t\tif e.IsDir() {", R_AU)
m(AJ, "\tif _, ok := v.Props[k]; !ok {\n\t\tv.Keys = append(v.Keys, k)\n\t}", "\tv.Keys = append(v.Keys, k)", R_AU)
m(AJ, "\t\tcase c < 0x20: // jq rejects", "\t\tcase false: // jq rejects", R_AU)
m(AJ, "\t\tcase r < 0x20 || r == 0x7f:", "\t\tcase r < 0x20:", R_AU)
m(AJ, '\t\t\tb.WriteString(`\\t`)', '\t\t\tb.WriteString(`\\u0009`)', R_AU)
m(AJ, 'ind := func(d int) { b.WriteString(strings.Repeat("  ", d)) }', 'ind := func(d int) { b.WriteString(strings.Repeat("    ", d)) }', R_AU)
m(AJ, '\t\tif len(v.Arr) == 0 {\n\t\t\tb.WriteString("[]")\n\t\t\treturn\n\t\t}', "", R_AU)
m(AJ, '\t\tif len(v.Keys) == 0 {\n\t\t\tb.WriteString("{}")\n\t\t\treturn\n\t\t}', "", R_AU)
m(AJ, "\t\tb.WriteString(v.Num)", "\t\tf, _ := strconv.ParseFloat(v.Num, 64)\n\t\tb.WriteString(strconv.FormatFloat(f, 'g', -1, 64))", R_AU)
m(AJ, "\tcase Null:\n\t\tv = NewObject()", "\tcase Null:\n\t\treturn v, fmt.Errorf(\"null\")", R_AU)
m(AJ, "\t\t\t\tb.WriteRune(rune(n))", "\t\t\t\tb.WriteString(p.s[p.i-6 : p.i])", R_AU)

LK = "internal/link/link.go"
LS = "internal/link/sync.go"
R_LK = "TestLinkGolden"
m(LK, '\tif i := strings.LastIndex(b, ":"); i >= 0 {\n\t\tb = b[i+1:]\n\t}', "", R_LK)
m(LK, '\tb := strings.TrimSuffix(url, "/")', "\tb := url", R_LK)
m(LK, '\tb = strings.TrimSuffix(b, ".git")', "", R_LK)
m(LK, '\tif st, err := os.Stat(d + "/.git"); err == nil && st.IsDir() {', '\tif config.Exists(d + "/.git") {', R_LK)
m(LK, '\t\tif comp != "" && comp != "." {', '\t\tif comp != "" {', R_LK)
m(LK, "\t\tif out == \"\" {\n\t\t\treturn \"/\"\n\t\t}", "", R_LK)
m(LK, '\tif out = strings.TrimPrefix(out, "/"); out == "" {\n\t\treturn "."', '\tif out = strings.TrimPrefix(out, "/"); out == "" {\n\t\treturn ""', R_LK)
m(LK, '\tif v == "/" || v == h {', '\tif v == h {', R_LK)
m(LK, '\tif strings.HasPrefix(v, ".") && len(v) > 1 || hiddenComp(v) { // .?*|*/.?*', '\tif hiddenComp(v) { // .?*|*/.?*', R_LK)
m(LK, "\tfor i := 0; i+2 < len(v); i++ {", "\tfor i := 0; i+1 < len(v); i++ {", R_LK,
  equivalent="a path ending in '/.' is normalized away before the check")
m(LK, 'dirs := []string{"/etc", "/root", "/proc", "/sys", "/boot"}', 'dirs := []string{"/etc", "/root", "/proc", "/sys"}', R_LK)
m(LK, '\t\tif v == d || strings.HasPrefix(v, d+"/") {', '\t\tif strings.HasPrefix(v, d) {', R_LK)
m(LK, 'if err == nil && (strings.HasPrefix(t, "/") || strings.Contains(t, "..")) {', 'if err == nil && strings.HasPrefix(t, "/") {', R_LK)
m(LK, "\t\t\tif frag != \"\" {\n\t\t\t\tcheck(frag)", "\t\t\tif false {\n\t\t\t\tcheck(frag)", R_LK)
m(LK, '\t\tif strings.HasPrefix(n, ".") || !strings.HasSuffix(n, ".yaml") {', '\t\tif !strings.HasSuffix(n, ".yaml") {', R_LK)
m(LK, "\t\tif config.Exists(filepath.Join(dir, n)) {\n\t\t\tout = append(out, n)", "\t\tif true {\n\t\t\tout = append(out, n)", R_LK)
m(LK, '\t\t\tcase "1", "2", "3":\n\t\t\tdefault:', '\t\t\tcase "1", "2", "3", "4":\n\t\t\tdefault:', R_LK)
m(LK, '\t\t\t\tif t == "" {\n\t\t\t\t\tt = "<none>"\n\t\t\t\t}', "", R_LK)
m(LK, '\t\t\tif repo := config.ExtractYAMLScalar(p, "default_repo"); repo != "" && DefaultRepoIsSensitive(c.Home, repo) {', '\t\t\tif repo := config.ExtractYAMLScalar(p, "default_repo"); false && DefaultRepoIsSensitive(c.Home, repo) {', R_LK)
m(LK, '\t\t\tif name := strings.TrimSuffix(f, ".yaml"); !IsValidName(name) {', '\t\t\tif name := strings.TrimSuffix(f, ".yaml"); false && !IsValidName(name) {', R_LK)
m(LK, '\tcase "off", "advisory", "required", "":', '\tcase "off", "advisory", "required", "", "requird":', R_LK)
m(LK, '\t\t\tif n := e.Name(); !strings.HasPrefix(n, ".") && config.Exists(filepath.Join(dir, n)) {', '\t\t\tif n := e.Name(); config.Exists(filepath.Join(dir, n)) {', R_LK)
m(LK, '"NOTICE": true, "docs": true,', '"NOTICE": true,', R_LK)
m(LK, "\tif len(problems) > 0 {\n\t\tr.warn(\"overlay failed validation:\")", "\tif len(problems) > 1 {\n\t\tr.warn(\"overlay failed validation:\")", R_LK)
m(LK, "\tif len(extra) > 0 {\n\t\tr.warn(fmt.Sprintf(\"overlay profiles request", "\tif len(extra) > 1 {\n\t\tr.warn(fmt.Sprintf(\"overlay profiles request", R_LK)
m(LK, '\t\tif !strings.HasPrefix(tp, "/") {\n\t\t\ttp = dir + "/" + tp\n\t\t}', "", R_LK)
m(LK, '\t\tif strings.HasPrefix(tp, "~") {\n\t\t\ttp = c.Home + tp[1:]\n\t\t}', "", R_LK)
m(LK, '\tif v := scalar("vetting_max_commits_behind"); allDigits.MatchString(v) {', '\tif v := scalar("vetting_max_commits_behind"); v != "" {', R_LK)
m(LK, '\t} else if v != "" && v != "false" {\n\t\tr.warn(fmt.Sprintf("overlay config.yaml sets vetting_exceptions_require_head', '\t} else if v != "" {\n\t\tr.warn(fmt.Sprintf("overlay config.yaml sets vetting_exceptions_require_head', R_LK)
m(LK, '\tif nCatalogue == 1 {\n\t\tentries = "y"', '\tif nCatalogue <= 1 {\n\t\tentries = "y"', R_LK)
m(LK, '\t\tif t != "" && t[0] != \'#\' {\n\t\t\tn++', '\t\tif t != "" {\n\t\t\tn++', R_LK)
m(LK, '\tif cur == managedDir {\n\t\tkeys = append([]string{"overlay"}, keys...)', '\tif true {\n\t\tkeys = append([]string{"overlay"}, keys...)', R_LK)
m(LK, '\tif strings.HasPrefix(cur, "~") {\n\t\tcur = c.Home + cur[1:]\n\t}', "", R_LK)
m(LS, "\tif c.NoLinkCheck || c.Git == \"\" || !c.IsActive() {", "\tif c.Git == \"\" || !c.IsActive() {", R_LK)
m(LS, '\ttarget := c.revParse(dir, "origin/"+ref+"^{commit}")', '\ttarget := c.revParse(dir, ref+"^{commit}")', R_LK)
m(LS, '\tif head == "" || target == "" || head == target {', '\tif head == "" || target == "" {', R_LK)
m(LS, '\tif st, _ := c.git(dir, "status", "--porcelain"); st != "" {', '\tif st, _ := c.git(dir, "status", "--porcelain", "--untracked-files=no"); st != "" {', R_LK)
m(LS, '\t\tif c.Home != "" && strings.HasPrefix(dir, c.Home) {', '\t\tif false {', R_LK)
m(LS, '\tif v := c.ValidateShape(dir); !v.OK {\n\t\tr.Stderr = append(r.Stderr, v.Stderr...)\n\t\trollback()', '\tif v := c.ValidateShape(dir); !v.OK {\n\t\tr.Stderr = append(r.Stderr, v.Stderr...)', R_LK)
m(LS, "\tif unmet != \"\" {\n\t\trollback()", "\tif unmet != \"\" {", R_LK)
m(LS, '\tif err := c.WriteConfig(dir, c.URL(), ref, target); err != nil {', '\tif err := c.WriteConfig(dir, c.URL(), ref, head); err != nil {', R_LK)
m(LS, '\tfor _, w := range warns {\n\t\twarn(w)\n\t}', "", R_LK)

OB = "internal/onboard/onboard.go"
R_OB = "TestOnboardGolden"
m(OB, '"COPILOT_GITHUB_TOKEN", "GH_TOKEN", "GITHUB_TOKEN", "GROK_DEPLOYMENT_KEY"}', '"COPILOT_GITHUB_TOKEN", "GITHUB_TOKEN", "GROK_DEPLOYMENT_KEY"}', R_OB)
m(OB, '\t\tif getenv(v) != "" {', '\t\tif true {', R_OB)
m(OB, "\tif !isRegular(src) {\n\t\treturn \"missing-src\", nil", "\tif !lexists(src) {\n\t\treturn \"missing-src\", nil", R_OB)
m(OB, '\tif isRegular(dst) && !c.Force {\n\t\treturn "skipped-exists", nil', '\tif lnoRegular(dst) && !c.Force {\n\t\treturn "skipped-exists", nil', R_OB)
m(OB, '\tif isRegular(dst) && !c.Force {\n\t\treturn "skipped-exists", nil', '\tif isRegular(dst) {\n\t\treturn "skipped-exists", nil', R_OB)
m(OB, "\tif c.DryRun {\n\t\treturn \"copied\", nil\n\t}\n\tos.MkdirAll", "\tos.MkdirAll", R_OB)
m(OB, "\tif lexists(dst) && !config.Exists(dst) { // a dangling symlink", "\tif false { // a dangling symlink", R_OB)
m(OB, "\tif st, err := os.Stat(dst); err == nil && st.IsDir() {\n\t\ttarget = filepath.Join(dst, filepath.Base(src))\n\t}", "", R_OB,
  equivalent="directory destinations are not in the corpus (the bash chmods the directory 0600, locking the harness out)")
m(OB, "\t\tos.WriteFile(target, data, st.Mode().Perm()) // cp keeps an existing file's mode", "\t\tos.WriteFile(target, data, 0o644) // cp keeps an existing file's mode", R_OB)
m(OB, "\tos.Chmod(dst, 0o600)\n\treturn \"copied\", nil\n}", "\treturn \"copied\", nil\n}", R_OB)
m(OB, '\t\to.say("  %s: staged %s → %s", agent, c.disp(src), c.disp(dst))', '\t\to.say("  %s: staged %s → %s", agent, src, c.disp(dst))', R_OB)
m(OB, '\t\tstage("claude", [2]string{h + "/.claude/.credentials.json", ah + "/.credentials.json"},\n\t\t\t[2]string{h + "/.claude/settings.json", ah + "/settings.json"})', '\t\tstage("claude", [2]string{h + "/.claude/.credentials.json", ah + "/.credentials.json"})', R_OB)
m(OB, "\t\tc.EnsureCodexSandboxMode(&o, ah+\"/config.toml\")", "", R_OB)
m(OB, "if isRegular(src) && grepE(src, `^[[:space:]]*(api_key|env_key)[[:space:]]*=`) {", "if isRegular(src) && grepE(src, `^[[:space:]]*api_key[[:space:]]*=`) {", R_OB)
m(OB, "\t\tc.EnsureGrokPrivacyConfig(&o, dst)", "", R_OB)
m(OB, '\t\treturn o, false\n\t}\n\treturn o, true', '\t\treturn o, true\n\t}\n\treturn o, true', R_OB)
m(OB, "\tif readable(cfg) && grepE(cfg, `^[[:space:]]*sandbox_mode[[:space:]]*=`) {", "\tif readable(cfg) && grepE(cfg, `^sandbox_mode[[:space:]]*=`) {", R_OB)
m(OB, '\t\trewrite(cfg, []byte(codexHeader+"\\n\\n"+catTrimmed(cfg)), true)', '\t\trewrite(cfg, []byte(codexHeader+"\\n\\n"+catTrimmed(cfg)), false)', R_OB)
m(OB, '\t\trewrite(cfg, []byte(codexHeader+"\\n\\n"+catTrimmed(cfg)), true)', '\t\trewrite(cfg, []byte(codexHeader+"\\n\\n"+catTrimmed(cfg)+"\\n"), true)', R_OB)
m(OB, '\treturn strings.TrimRight(strings.ReplaceAll(string(b), "\\x00", ""), "\\n")', '\treturn string(b)', R_OB)
m(OB, "\tif readable(cfg) && grepE(cfg, `^[[:space:]]*\\[(harness|telemetry)\\]`) {", "\tif readable(cfg) && grepE(cfg, `^\\[(harness|telemetry)\\]`) {", R_OB)
m(OB, '\t\trewrite(cfg, []byte(catTrimmed(cfg)+"\\n\\n"+grokBlock+"\\n"), true)', '\t\trewrite(cfg, []byte(grokBlock+"\\n"), true)', R_OB)
m(OB, '\t\tos.WriteFile(cfg+".tmp", data, 0o644)\n\t\tos.Rename(cfg+".tmp", cfg)', '\t\tos.WriteFile(cfg, data, 0o644)', R_OB)
m(OB, "\tif isRegular(dst) && !c.Force {\n\t\to.say(\"  config: %s already exists", "\tif isRegular(dst) {\n\t\to.say(\"  config: %s already exists", R_OB)
m(OB, '\t\to.say("  config: would write starter %s", d)\n\t\treturn', '\t\to.say("  config: would write starter %s", d)', R_OB)

AG = "internal/agents/agents.go"
R_AG = "TestAgentsGolden"
m(AG, 'var Valid = []string{"claude", "codex", "opencode", "copilot", "grok"}', 'var Valid = []string{"claude", "codex", "opencode", "copilot"}', R_AG)
m(AG, '"console.anthropic.com", "statsig.anthropic.com", "sentry.io"},', '"console.anthropic.com", "statsig.anthropic.com"},', R_AG)
m(AG, '"grok": {"api.x.ai", "accounts.x.ai", "auth.x.ai", "grok.com"},', '"grok": {"api.x.ai", "accounts.x.ai", "grok.com"},', R_AG)
m(AG, "\tif i := strings.Index(h, \"://\"); i >= 0 {\n\t\th = h[i+3:]\n\t}", "", R_AG)
m(AG, '\tif i := strings.LastIndex(h, "@"); i >= 0 {', '\tif i := strings.Index(h, "@"); i >= 0 {', R_AG)
m(AG, "\tif i := strings.Index(h, \":\"); i >= 0 {\n\t\th = h[:i]\n\t}\n\treturn h", "\treturn h", R_AG)
m(AG, "\tif i := strings.Index(h, \"/\"); i >= 0 {\n\t\th = h[:i]\n\t}", "", R_AG)
m(AG, "\tif baseURL != \"\" {\n\t\treturn nil, fmt.Errorf(\"ERROR: OPENCODE_BASE_URL ('%s') has no host.", "\tif false {\n\t\treturn nil, fmt.Errorf(\"ERROR: OPENCODE_BASE_URL ('%s') has no host.", R_AG)
m(AG, '\t\treturn "--sandbox danger-full-access"', '\t\treturn "--sandbox"', R_AG)
m(AG, 'func SupportsMCP(agent string) bool { return agent == "claude" }', 'func SupportsMCP(agent string) bool { return agent != "" }', R_AG)
m(AG, '\t\treturn []string{"--mcp-config", MCPConfigDir + "/" + MCPConfigFile, "--strict-mcp-config"}', '\t\treturn []string{"--mcp-config", MCPConfigDir + "/" + MCPConfigFile}', R_AG)
m(AG, "\t\tif rec == \"\" {\n\t\t\tcontinue\n\t\t}", "", R_AG)
m(AG, "\t\ttransport, url := rest, rest", "\t\ttransport, url := rest, \"\"", R_AG)
m(AG, "\t\tservers, _ = servers.Set(name, entry)", "\t\tservers, _ = servers.Set(transport, entry)", R_AG)
m(AG, '\tcase "opencode":\n\t\treturn "apikey"', '\tcase "opencode":\n\t\treturn "oauth"', R_AG)
m(AG, '"KUBERNETES_SERVICE_PORT", "COPILOT_GITHUB_TOKEN", "GH_TOKEN", "GITHUB_TOKEN", "GROK_DEPLOYMENT_KEY"}', '"KUBERNETES_SERVICE_PORT", "COPILOT_GITHUB_TOKEN", "GH_TOKEN", "GITHUB_TOKEN"}', R_AG)
m(AG, 'HostEnvBlocklistPrefixes = []string{"OS_", "AWS_", "GOOGLE_", "AZURE_", "TELEPORT_", "TSH_", "ANTHROPIC_", "OPENAI_"}', 'HostEnvBlocklistPrefixes = []string{"OS_", "AWS_", "GOOGLE_", "AZURE_", "TELEPORT_", "ANTHROPIC_", "OPENAI_"}', R_AG)
m(AG, '\t\tif val[v] != "" {\n\t\t\twarn(v)', '\t\tif _, ok := val[v]; ok {\n\t\t\twarn(v)', R_AG)
m(AG, '\t\t\tfor _, line := range strings.Split(e, "\\n") {', '\t\t\tfor _, line := range []string{e} {', R_AG)
m(AG, "\tif n > 0 {\n\t\tstdout = append(stdout,", "\tif true {\n\t\tstdout = append(stdout,", R_AG)

CL = "internal/cli/profile.go"
R_CL = "TestCLIGolden"
m(CL, '\tcase "list", "ls":', '\tcase "list":', R_CL)
m(CL, '\tcase "delete", "rm", "remove":', '\tcase "delete", "rm":', R_CL)
m(CL, '\tif strings.HasPrefix(a, flag+"=") {', '\tif strings.HasPrefix(a, flag) {', R_CL)
m(CL, '\tif tierV == "" {\n\t\tc.die("profile save: --tier is required.")', '\tif false {\n\t\tc.die("profile save: --tier is required.")', R_CL)
m(CL, '\tif len(repos) > 1 {', '\tif len(repos) > 2 {', R_CL)
m(CL, "\t\tif strings.HasPrefix(repo, \"~\") {\n\t\t\trepo = c.env.Home + repo[1:]\n\t\t}", "", R_CL)
m(CL, '\t\tif st, err := os.Stat(repo); err != nil || !st.IsDir() {', '\t\tif _, err := os.Stat(repo); err != nil {', R_CL)
m(CL, '\tif tierV != "1" && repo == "" {', '\tif tierV == "3" && repo == "" {', R_CL)
m(CL, '\t\tcase base != "" && agent != "":\n\t\t\tname = base + "-" + agent', '\t\tcase base != "" && agent != "":\n\t\t\tname = base', R_CL)
m(CL, '\t\t\tname = "tier" + tierV', '\t\t\tname = "tier"', R_CL)
m(CL, '\tif config.Exists(path) && !force {', '\tif config.IsFile(path) && !force {', R_CL)
m(CL, '\tos.Chmod(path, 0o644)', '\tos.Chmod(path, 0o600)', R_CL)
m(CL, '\tyaml = strings.TrimRight(yaml, "\\n") // "$(render_profile_yaml ...)"', '', R_CL)
m(CL, '\t\t\tif config.IsFile(userDir + "/" + name + ".yaml") {\n\t\t\t\tcontinue', '\t\t\tif false {\n\t\t\t\tcontinue', R_CL)
m(CL, '\t\tif !strings.HasPrefix(n, ".") && strings.HasSuffix(n, ".yaml") && config.Exists(dir+"/"+n) {', '\t\tif strings.HasSuffix(n, ".yaml") && config.Exists(dir+"/"+n) {', R_CL)
m(CL, 'return padRight(name, 24) + "  " + padRight(source, 7)', 'return padRight(name, 20) + "  " + padRight(source, 7)', R_CL)
m(CL, '\t\t\torOverlay = " or the overlay"', '\t\t\torOverlay = ""', R_CL)
m(CL, '\tc.out("# %s", c.tilde(path))', '\tc.out("# %s", path)', R_CL)
m(CL, '\t\tif resolved, ok := config.FindProfilePath(c.env.Env, name); ok {', '\t\tif resolved, ok := config.FindProfilePath(c.env.Env, name); false && ok {', R_CL)
m(CL, '\t\tcase "y", "Y", "yes", "YES":', '\t\tcase "y", "Y":', R_CL)
m(CL, '\t\t\tif name != "" {\n\t\t\t\tc.die("Unexpected argument: %s", a)', '\t\t\tif false {\n\t\t\t\tc.die("Unexpected argument: %s", a)', R_CL)

WS = "internal/workspace/workspace.go"
CK2 = "internal/cli/check.go"
m(WS, '\treturn []string{h + "/.tsh", h + "/.kube", h + "/.ssh", h + "/.config/openstack", h + "/.aws",', '\treturn []string{h + "/.tsh", h + "/.kube", h + "/.config/openstack", h + "/.aws",', R_CL, pkg="cli")
m(WS, '\tif exec.Command("git", "-C", repo, "rev-parse", "--git-dir").Run() != nil {', '\tif false {', R_CL, pkg="cli")
m(WS, '\tunder := func(p string) bool { return r == p || strings.HasPrefix(r, p+"/") }', '\tunder := func(p string) bool { return r == p }', R_CL, pkg="cli")
m(WS, '\tunder := func(p string) bool { return r == p || strings.HasPrefix(r, p+"/") }', '\tunder := func(p string) bool { return r == p || strings.HasPrefix(r, p) }', R_CL, pkg="cli")
m(WS, '\tif h, _ := realpath(c.Home); r == fold(h) {', '\tif false {', R_CL, pkg="cli")
m(WS, '\tprotected = append(protected, c.Home+"/.sandbox")', '', R_CL, pkg="cli")
m(WS, '\t\tif under(rp) || strings.HasPrefix(rp, r+"/") {', '\t\tif under(rp) {', R_CL, pkg="cli")
m(WS, '\tif ov := config.ResolveOverlayPath(c.Env); ov != "" {\n\t\tprotected = append(protected, ov)\n\t}', '', R_CL, pkg="cli")
m(WS, '\treturn filepath.Join(dir, filepath.Base(abs)), true', '\treturn abs, true', R_CL, pkg="cli")
m(WS, '\t\tif d.IsDir() && depth >= 3 {', '\t\tif d.IsDir() && depth >= 2 {', R_CL, pkg="cli")
m(WS, '\t\tif match(d.Name()) && !strings.Contains(shown, "/.git/") {', '\t\tif match(d.Name()) {', R_CL, pkg="cli")
m(WS, '\t\treturn n == ".env" || bashcompat.Glob(".env.*", n) || bashcompat.Glob("*.env", n)', '\t\treturn n == ".env" || bashcompat.Glob(".env.*", n)', R_CL, pkg="cli")
m(WS, 'var credPatterns = []string{"clouds.yaml", "kubeconfig", ".npmrc", "*-openrc.sh", "*.pem", "*.key", "*.pfx", "id_rsa", "id_ed25519"}', 'var credPatterns = []string{"clouds.yaml", "kubeconfig", ".npmrc", "*-openrc.sh", "*.pem", "*.pfx", "id_rsa", "id_ed25519"}', R_CL, pkg="cli")
m(WS, '\t\tif strings.HasSuffix(start, "/") {\n\t\t\treturn start + rel\n\t\t}', '', R_CL, pkg="cli")
m(WS, '\tif issues > 0 {\n\t\tout = append(out, "",', '\tif issues > 1 {\n\t\tout = append(out, "",', R_CL, pkg="cli")
m(CK2, '\tif len(args) == 0 || args[0] == "" {', '\tif len(args) == 0 {', R_CL)
m(CK2, "\tif strings.HasPrefix(ws, \"~\") {\n\t\tws = c.env.Home + ws[1:]\n\t}", "", R_CL)
m(CK2, '\tif len(config.LoadRepoAcceptedSecrets(ws)) > 0 {', '\tif false {', R_CL)
m(CK2, '\t\tif rel == "" {\n\t\t\tcontinue\n\t\t}', '', R_CL,
  equivalent="the tab-IFS read merges an empty path field into the next (SplitTab reproduces it), so the path is never empty here")
m(CK2, '\t\tcase "no", "gitconfig":', '\t\tcase "no":', R_CL)
m(CK2, '\t\t\t\tentries = append(entries, ws+"\\t"+rel+"\\t"+rule+"\\t"+ln+"\\t"+match)', '\t\t\t\tentries = append(entries, ws+"\\t"+rel+"\\t"+rule+"\\t"+ln)', R_CL)
m(CK2, '\tif encrypted > 0 {', '\tif encrypted > 1 {', R_CL)
m(CK2, '\tcase failed:', '\tcase false:', R_CL)
m(CK2, '\t\tif gitconfig > 0 {', '\t\tif gitconfig > 1 {', R_CL)
m(CK2, '\t\t\tgate.PrintExceptionsAddCommands(c.stdout, entries)', '', R_CL)

MK = "internal/cli/mask.go"
m(MK, '\tif strings.HasPrefix(rel, "/") || strings.HasPrefix(rel, "../") || strings.Contains(rel, "/../") {', '\tif strings.HasPrefix(rel, "/") || strings.Contains(rel, "/../") {', R_CL)
m(MK, '\tif strings.HasPrefix(rel, "/") || strings.HasPrefix(rel, "../") || strings.Contains(rel, "/../") {', '\tif strings.HasPrefix(rel, "/") || strings.HasPrefix(rel, "../") {', R_CL)
m(MK, '\tif len(rels) == 0 {\n\t\tc.die("mask add: at least one RELPATH is required.")', '\tif false {\n\t\tc.die("mask add: at least one RELPATH is required.")', R_CL)
m(MK, '\t\t\tcase st.IsDir():\n\t\t\t\tstored = bare + "/"', '\t\t\tcase st.IsDir():\n\t\t\t\tstored = bare', R_CL)
m(MK, '\t\t\tcase st.Mode().IsRegular():\n\t\t\t\tstored = bare\n\t\t\tdefault:', '\t\t\tdefault:\n\t\t\t\tstored = bare\n\t\t\tcase false:', R_CL)
m(MK, '\t\t} else if strings.HasSuffix(rel, "/") {', '\t\t} else if false {', R_CL)
m(MK, '\t\tif workspace.PathHasTrackedContent(repo, bare) {', '\t\tif false {', R_CL)
m(MK, '\tc.out("  %s/  (directory)", gate.MaskedDirPath)', '\tc.out("  %s/", gate.MaskedDirPath)', R_CL)
m(MK, '\t\t\tif isDir(repo + "/" + strings.TrimSuffix(p, "/")) {', '\t\t\tif true {', R_CL)
m(MK, '\t\tcase config.IsFile(repo + "/" + p):', '\t\tcase config.Exists(repo + "/" + p):', R_CL)
m(MK, '\tif !deviation.Fixed(deviation.MaskListStatus) {\n\t\tpanic(exit(1))\n\t}', '', R_CL)
m("internal/workspace/workspace.go", '\tif strings.TrimSpace(firstLine(git("ls-files", "--", ":(literal)"+relpath))) != "" {\n\t\treturn true\n\t}', '', R_CL, pkg="cli")
m("internal/workspace/workspace.go", '\treturn strings.TrimRight(git("log", "--all", "-1", "--format=%H", "--", ":(literal)"+relpath), "\\n") != ""', '\treturn false', R_CL, pkg="cli")

EXC = "internal/cli/exceptions.go"
m(EXC, '\t\tif !strings.Contains(rest, ":") || relpath == "" || rule == "" || !lineDigits.MatchString(line) {', '\t\tif !strings.Contains(rest, ":") || relpath == "" || !lineDigits.MatchString(line) {', R_CL)
m(EXC, '\t\tif strings.HasPrefix(relpath, "/") || strings.HasPrefix(relpath, "../") || strings.Contains(relpath, "/../") {', '\t\tif strings.HasPrefix(relpath, "/") {', R_CL)
m(EXC, '\t\tif i := strings.LastIndex(rest, ":"); i >= 0 {\n\t\t\trule, relpath = rest[i+1:], rest[:i]', '\t\tif i := strings.Index(rest, ":"); i >= 0 {\n\t\t\trule, relpath = rest[i+1:], rest[:i]', R_CL)
m(EXC, '\t\tcase 1:\n\t\t\tc.die("exceptions add: no %s finding', '\t\tcase 9:\n\t\t\tc.die("exceptions add: no %s finding', R_CL)
m(EXC, '\t\t\tfor _, l := range strings.Split(fp, "\\n") {', '\t\t\tfor _, l := range []string{fp} {', R_CL)
m(EXC, '\tif _, err := exec.LookPath("betterleaks"); err != nil {\n\t\tc.die("exceptions add: betterleaks is required', '\tif false {\n\t\tc.die("exceptions add: betterleaks is required', R_CL)
m(EXC, '\tif !any {\n\t\tc.out("  (none)")\n\t}\n\tlegacy := false', '\tlegacy := false', R_CL)
m(EXC, '\t\treturn strings.TrimLeft(l[i+1:], " \\t\\n\\v\\f\\r")', '\t\treturn l[i+1:]', R_CL)
m(EXC, '\t\ti := strings.LastIndex(l, "#")', '\t\ti := strings.Index(l, "#")', R_CL)
m(EXC, '\t\tif strings.Count(fp, ":") < 2 {\n\t\t\tfp = entry\n\t\t}', '', R_CL)
m(EXC, '\tconfig.RemoveYAMLList(cfg, "accepted_secrets")', '', R_CL)
m(EXC, '\tif len(entries) == 0 {\n\t\tc.out("No accepted_secrets: entries', '\tif false {\n\t\tc.out("No accepted_secrets: entries', R_CL)
m("internal/gate/scan.go", '\t\tif file == target && r == rule && isNum && n == float64(want) {', '\t\tif file == target && r == rule && isNum {', R_CL, pkg="cli")
m("internal/gate/scan.go", '\t\tif file == target && r == rule && isNum && n == float64(want) {', '\t\tif file == target && isNum && n == float64(want) {', R_CL, pkg="cli")
m("internal/gate/scan.go", '\tif okRun, _ := betterleaksRun(e, realRepo, reportPath, cfgPath, ignore, ""); !okRun {\n\t\treturn nil, 2', '\tif okRun, _ := betterleaksRun(e, realRepo, reportPath, cfgPath, ignore, ""); false && !okRun {\n\t\treturn nil, 2', R_CL, pkg="cli")

VT = "internal/cli/vet.go"
m(VT, '\t\tcase a == "--status":\n\t\t\tstatus = true', '\t\tcase a == "--status":\n\t\t\tstatus = false', R_CL)
m(VT, '\t\tcase a == "--yes" || a == "-y":\n\t\t\tyes = "true"', '\t\tcase a == "--yes" || a == "-y":\n\t\t\tyes = "false"', R_CL)
m(VT, '\t\tc.out("  signer: %s", or(f4, "unknown"))', '\t\tc.out("  signer: %s", f4)', R_CL,
  equivalent="a verified tag always has a signer (vetting reports \"unknown\" itself when it has none)")
m(VT, '\t\tif vetting.NumCmp(or(f5, "0"), "0", "eq") {', '\t\tif vetting.NumCmp(or(f5, "0"), "1", "eq") {', R_CL)
m(VT, '\t\tif age != "" {', '\t\tif age == "" {', R_CL)
m(VT, '\t\t\tcase vetting.NumCmp(age, cap, "gt"):', '\t\t\tcase vetting.NumCmp(age, cap, "eq"):', R_CL)
m(VT, '\tcase "dirty":\n\t\tc.out("DIRTY:    %s (HEAD %s)", repo, f2)', '\tcase "dirtyx":\n\t\tc.out("DIRTY:    %s (HEAD %s)", repo, f2)', R_CL)
m(VT, '\t\tc.errOut("ERROR:    %s", f2)\n\t\tpanic(exit(1))', '\t\tc.errOut("ERROR:    %s", f2)', R_CL)
m(VT, '\tif a.SigningSetupAssist(repo) != 0 {\n\t\tpanic(exit(1))\n\t}', '', R_CL,
  equivalent="not covered on purpose: the setup assist fails with git's own text, which differs between git versions")
m(VT, '\tif rc := a.AttestRepo(repo, msg, yes); rc != 0 {', '\tif rc := a.AttestRepo(repo, "vetted for agent use", yes); rc != 0 {', R_CL)

LKC = "internal/cli/link.go"
FET = "internal/gate/fetch.go"
m(LKC, '\tif l.IsActive() {\n\t\tc.die("A link is already active', '\tif false {\n\t\tc.die("A link is already active', R_CL)
m(LKC, '\tif config.Exists(dir) {\n\t\tc.die("%s already exists.', '\tif false {\n\t\tc.die("%s already exists.', R_CL)
m(LKC, '\tif ov := config.ExtractYAMLScalar(c.env.UserConfig, "overlay"); ov != "" {\n\t\tc.warn("existing', '\tif ov := ""; ov != "" {\n\t\tc.warn("existing', R_CL)
m(LKC, '\tif !v.OK {\n\t\tos.RemoveAll(dir)\n\t\tc.die("overlay at', '\tif false {\n\t\tos.RemoveAll(dir)\n\t\tc.die("overlay at', R_CL)
m(LKC, '\tif unmet != "" {\n\t\tos.RemoveAll(dir)', '\tif false {\n\t\tos.RemoveAll(dir)', R_CL)
m(LKC, '\tif target != "" && head != target {', '\tif target != "" {', R_CL)
m(LKC, '\tif st, _ := gitRun(l, dir, "status", "--porcelain"); st != "" {', '\tif false {', R_CL)
m(LKC, '\tif old == target {\n\t\tl.WriteConfig', '\tif false {\n\t\tl.WriteConfig', R_CL)
m(LKC, '\tif !v.OK {\n\t\trollback()', '\tif !v.OK {', R_CL)
m(LKC, '\tif !keep && dir != "" && isDir(dir) {', '\tif dir != "" && isDir(dir) {', R_CL)
m(LKC, '\t\tsuffix := " and delete its clone"', '\t\tsuffix := ""', R_CL)
m(LKC, '\tif d == "" && l.IsActive() && config.ExtractYAMLScalar(c.env.UserConfig, "overlay") != "" &&', '\tif false &&', R_CL)
m(FET, '\tif url == "" {\n\t\treturn\n\t}', '', R_CL, pkg="cli")
m(FET, '\tif strings.HasPrefix(url, "-") {', '\tif false {', R_CL, pkg="cli")
m(FET, '\t\tif config.IsFile(cache) {', '\t\tif true {', R_CL, pkg="cli")

SS = "internal/cli/sessions.go"
m(SS, '\t\tcase x.Kind == jqjson.Null || (x.Kind == jqjson.Bool && !x.B):', '\t\tcase x.Kind == jqjson.Null:', R_CL)
m(SS, '\t\t\treturn strings.TrimRight(strings.Join(append(out, def), "\\n"), "\\n")', '\t\t\treturn def', R_CL)
m(SS, '\t\t\treturn strings.TrimRight(strings.Join(append(out, def), "\\n"), "\\n")', '\t\t\treturn strings.Join(append(out, def), "\\n")', R_CL)
m(SS, '\t\tcase jqjson.Null:\n\t\tdefault:', '\t\tdefault:', R_CL)
m(SS, '\t\tif strings.HasPrefix(e.Name(), "ses-") && isDir(filepath.Join(logs, e.Name())) {', '\t\tif strings.HasPrefix(e.Name(), "ses-") && e.IsDir() {', R_CL)
m(SS, '\t\t\tfmt.Fprintf(c.stdout, "  %s  (no session.json)\\n", padRight(sid, 36))', '\t\t\tfmt.Fprintf(c.stdout, "  %s  (no session.json)\\n", sid)', R_CL)
m(SS, 'padRight(agent, 10), padRight(tier, 2),', 'padRight(agent, 10), padRight(tier, 3),', R_CL)
m(SS, '\tif !found {\n\t\tc.out("  (no sessions found)")', '\tif found {\n\t\tc.out("  (no sessions found)")', R_CL)
m(SS, '\t\tsort.Strings(files)\n', '', R_CL)
m(SS, '\t\t\tif err == nil && d.Type().IsRegular() {', '\t\t\tif err == nil {', R_CL)
m(SS, '\t\t\tif !strings.HasPrefix(e.Name(), "ses-") || !e.IsDir() {', '\t\t\tif !strings.HasPrefix(e.Name(), "ses-") {', R_CL)
m(SS, '\t\tif d != days {\n\t\t\tn = -n\n\t\t}', '', R_CL)
m(SS, '\t\t\tif age := now.Sub(st.ModTime()); age > 0 && int64(age/(24*time.Hour)) > n {', '\t\t\tif age := now.Sub(st.ModTime()); age > 0 && int64(age/(24*time.Hour)) >= n {', R_CL)

RN = "internal/cli/run.go"
m(RN, 's := LaunchSpec{Agent: "claude", Tier: "1"}', 's := LaunchSpec{Agent: "claude", Tier: "2"}', R_CL)
m(RN, '\tfor i := range s.Repos {\n\t\ts.Repos[i] = c.tildeExpand(s.Repos[i])\n\t}', '', R_CL)
m(RN, '\t\t\ts.HomeDir = c.tildeExpand(homedir)', '\t\t\ts.HomeDir = homedir', R_CL)
m(RN, '\tl.NoLinkCheck = c.env.NoLinkCheck', '', R_CL)
m(RN, '\t\tif unmet != "" {', '\t\tif unmet == "x" {', R_CL)
m(RN, '\t\t\tif tierExplicit && s.Tier != profile {', '\t\t\tif s.Tier != profile {', R_CL)
m(RN, '\t\t\tif tierExplicit && s.Tier != pt {', '\t\t\tif s.Tier != pt {', R_CL)
m(RN, 'if dr := config.ExtractYAMLScalar(p, "default_repo"); dr != "" && len(s.Repos) == 0 {', 'if dr := config.ExtractYAMLScalar(p, "default_repo"); dr != "" {', R_CL)
m(RN, '\t\t\t\ts.Repos = append(s.Repos, c.tildeExpand(dr))', '\t\t\t\ts.Repos = append(s.Repos, dr)', R_CL)
m(RN, 's.MCPs = strings.Join(config.ExtractYAMLList(p, "mcps"), ",")', 's.MCPs = strings.Join(config.ExtractYAMLList(p, "mcps"), " ")', R_CL)
m(RN, '\tif s.BaseURL != "" {\n\t\tbaseURL = s.BaseURL\n\t}', '', R_CL)
m("internal/cli/bindings.go", '\treturn c.env.OpencodeAPIKey != ""', '\treturn c.env.OpencodeAPIKey != "x"', R_CL)
m(RN, '\t\tif !httpURL.MatchString(baseURL) {', '\t\tif false {', R_CL)
m(RN, '\tif s.Tier != "1" && len(s.Repos) == 0 {', '\tif s.Tier == "2" && len(s.Repos) == 0 {', R_CL)
m(RN, 'c.env.ImagePresent(image) == 1 {', 'c.env.ImagePresent(image) != 0 {', R_CL)
m(RN, '\tif len(s.Repos) > 1 {\n\t\tif dup', '\tif len(s.Repos) > 2 {\n\t\tif dup', R_CL)
m(RN, '\t\t\tif envName.MatchString(name) {', '\t\t\tif true {', R_CL)
m(RN, '\t\tseen = append(seen, env)\n', '', R_CL)
m(RN, '\t\tif len(pairs) == 0 && len(s.InfraKubeconfigs) == 0 {', '\t\tif len(pairs) == 0 {', R_CL)
m(RN, '\t} else if len(s.InfraKubeconfigs) > 0 {\n\t\tc.die("--infra-kubeconfig is only valid for tier 3.")', '\t} else if false {\n\t\tc.die("--infra-kubeconfig is only valid for tier 3.")', R_CL)
m(RN, '\tif s.InfraKubeContext != "" && len(s.InfraKubeconfigs) == 0 {', '\tif false {', R_CL)
m(RN, '\t\tif !config.IsFile(rc) {\n\t\t\tcontinue\n\t\t}', '', R_CL)
m(RN, '\t\t\tif !in {\n\t\t\t\tungranted', '\t\t\tif in {\n\t\t\t\tungranted', R_CL)
m(RN, '\t\tif honor == "true" {\n\t\t\te("==> NOTICE', '\t\tif honor != "true" {\n\t\t\te("==> NOTICE', R_CL)
m(RN, '\t\tif h := urlHost(ep); h != "" {\n\t\t\tegress(h)', '\t\tif h := urlHost(ep); h == "x" {\n\t\t\tegress(h)', R_CL)
m(RN, '\tif err := chk.CheckBlockedCIDRsValid(); err != nil {', '\tif err := chk.CheckBlockedCIDRsValid(); false && err != nil {', R_CL)
m(RN, '\t\t\tcase len(name) > 64:', '\t\t\tcase len(name) > 65:', R_CL)
m(RN, '\t\t\tif !c.secretPresent(name) {', '\t\t\tif false {', R_CL)
m(RN, '\t\tif len(s.Secrets) > 0 {\n\t\t\ts.HasSecrets = true', '\t\tif len(s.Secrets) > 1 {\n\t\t\ts.HasSecrets = true', R_CL)
m(RN, '\t\t\tif echoOpt.MatchString(s) {', '\t\t\tif false {', R_CL)
m(RN, '\t\tfor _, s := range config.BashGlob(w) {', '\t\tfor _, s := range []string{w} {', R_CL)
m(RN, '\t\tfor _, tok := range strings.Fields(r) {', '\t\tfor _, tok := range []string{r} {', R_CL)
m(RN, '\tif i := strings.LastIndex(r, ":"); i >= 0 {\n\t\tr = r[:i]\n\t}\n\treturn r', '\treturn r', R_CL)
m(RN, '\tif i := strings.Index(r, "/"); i >= 0 {\n\t\tr = r[:i]\n\t}', '', R_CL)

RP = "internal/cli/runprep.go"
m(RP, 'return "ses-" + t.Format("20060102") + "-" + t.Format("150405")', 'return "ses-" + t.Format("20060102") + "-" + t.Format("150504")', R_CL)
m(RP, 'h[0:8], h[8:12], h[13:16], n&0x3|0x8,', 'h[0:8], h[8:12], h[12:15], n&0x3|0x8,', R_CL)
m(RP, 'h[0:8], h[8:12], h[13:16], n&0x3|0x8,', 'h[0:8], h[8:12], h[13:16], n|0x8,', R_CL)
m(RP, '\tif echoOption.MatchString(s) {\n\t\ts = ""\n\t}\n\tvar b strings.Builder', '\tvar b strings.Builder', R_CL)
m(RP, 'for _, ch := range []byte(asciiLower(s) + "\\n") {', 'for _, ch := range []byte(s + "\\n") {', R_CL)
m(RP, '\t\tok := ch >= \'a\' && ch <= \'z\' || ch >= \'0\' && ch <= \'9\'', '\t\tok := ch >= \'a\' && ch <= \'z\' || ch >= \'0\' && ch <= \'9\' || ch == \'-\'', R_CL)
m(RP, '\treturn strings.Trim(b.String(), "-")', '\treturn strings.TrimRight(b.String(), "-")', R_CL)
m(RP, '\tif m, _ := strconv.Atoi(max); len(pending) > m {', '\tif m, _ := strconv.Atoi(max); len(pending) > m+1 {', R_CL)
m(RP, '\t\tif w.kind != kind {', '\t\tif false {', R_CL)
m(RP, '\t\t\tif !c.secretPresent(s) {', '\t\t\tif false {', R_CL)
m(RP, '\t\t\tif !agents.SupportsMCP(agent) {', '\t\t\tif false {', R_CL)
m(RP, 'catalogue.Field(path, "mcp_path", "/mcp")', 'catalogue.Field(path, "mcp_path", "/sse")', R_CL,
  equivalent="the only MCP entry in the corpus sets mcp_path")
m(RP, 'catalogue.Field(path, "mcp_transport", "http")', 'catalogue.Field(path, "mcp_transport", "sse")', R_CL,
  equivalent="the only MCP entry in the corpus sets mcp_transport")
m(RP, '\t\tif err := cat.ValidateEntry(path, w.name); err != nil {', '\t\tif err := cat.ValidateEntry(path, w.name); false && err != nil {', R_CL)
m(RP, '\tif t, _ := strconv.Atoi(s.Tier); t >= 2 && len(s.Repos) > 0 {\n\t\tc.out("==> Running', '\tif t, _ := strconv.Atoi(s.Tier); t >= 3 && len(s.Repos) > 0 {\n\t\tc.out("==> Running', R_CL)
m(RP, '\t\t\tfor _, l := range workspace.Prescan(r) {', '\t\t\tfor _, l := range workspace.Prescan(r)[:0] {', R_CL)
m(RP, 'rc, sum := vd.VettingGateRepos(v.ResolvePosture(), tf(acceptUnvettedFlag), tf(acceptDrift), repos)', 'rc, sum := vd.VettingGateRepos(v.ResolvePosture(), tf(acceptUnvettedFlag), tf(acceptUnvettedFlag), repos)', R_CL)
m(RP, '\tif rc != 0 {\n\t\tpanic(exit(rc))\n\t}\n\tvettingSummary = sum', '\tvettingSummary = sum', R_CL)
m(RP, '\tacceptUnvetted := acceptUnvettedFlag && v.ForbidUnvettedOverride() != "true"', '\tacceptUnvetted := acceptUnvettedFlag', R_CL)
m(RP, 'TrustRoots: v.TrustRoots(),', 'TrustRoots: nil,', R_CL)
m(RP, 'Cap: v.MaxCommitsBehind(),', 'Cap: "",', R_CL)
m(RP, '\trc, sum = gate.SecretGateRepos(gd, tf(acceptUnmasked),', '\trc, sum = gate.SecretGateRepos(gd, tf(acceptUnvettedFlag),', R_CL)
m(RP, '\tif rc != 0 {\n\t\tpanic(exit(rc))\n\t}\n\tsecretSummary = sum', '\tsecretSummary = sum', R_CL)
m(RP, '\t\tcase 1:\n\t\t\ts.Name = bashcompat.Basename(s.Repos[0]) + "/" + s.Agent', '\t\tcase 1:\n\t\t\ts.Name = "multi/" + s.Agent', R_CL)
m(RP, '\tif s.Name == "" {\n\t\tswitch', '\tif s.Name == "x" {\n\t\tswitch', R_CL)
m(RP, 'rec.ID[strings.LastIndex(rec.ID, "-")+1:]', 'rec.ID[strings.Index(rec.ID, "-")+1:]', R_CL)
m(RP, 'for _, d := range append(append(ad, tier.Domains(s.Tier)...), s.Domains...) {', 'for _, d := range append(ad, s.Domains...) {', R_CL)
m(RP, '|| seen[d] {', '|| false {', R_CL)
m(RP, 'User: c.env.User,', 'User: "",', R_CL)
m(RP, 'Overlay: s.Overlay, InfraToken: len(s.InfraTokens) > 0,', 'Overlay: s.Overlay, InfraToken: false,', R_CL)
m(RP, '\tif agents.SessionIDFlag(s.Agent) != "" {', '\tif true {', R_CL)
m(RP, '\t\taudit.LogEvent(rec.LogDir, "vetting", vettingSummary, c.stamp())', '', R_CL)
m(RP, '\taudit.FlushOverrides(rec.LogDir, overrides, c.stamp())', '', R_CL)
m(RP, '\t\t*overrides = append(*overrides, audit.RecordOverride(m, what, repos...))', '', R_CL)
m(RP, '\tif c.env.StdinTTY {\n\t\tstdin = c.stdin\n\t}', '\tstdin = c.stdin', R_CL,
  equivalent="the gate reads its prompt only on a terminal, and the corpus has none")

AL = "internal/cli/allow.go"
m(AL, '\tif len(args) == 0 {\n\t\tc.usage("usage_allow")\n\t}\n\tvar sessionID', '\tvar sessionID', R_CL)
m(AL, '\t\tif sessionID != "" {\n\t\t\tc.die("Unexpected extra', '\t\tif false {\n\t\t\tc.die("Unexpected extra', R_CL)
m(AL, '\tif len(add) == 0 {', '\tif len(add) < 0 {', R_CL)
m(AL, '\t\t\tw, err = chk.CheckDomainNotBlocked(d)', '\t\t\tw, err = chk.CheckEgressTargetNotBlocked(d)', R_CL)
m(AL, '\tif err := chk.CheckBlockedCIDRsValid(); err != nil {', '\tif err := chk.CheckBlockedCIDRsValid(); false && err != nil {', R_CL)
m(AL, '\tif pod == "" {\n\t\tpod = "sandbox-" + sessionID\n\t}', '', R_CL)
m(AL, '\tif !c.env.SessionLive(sessionID, pod) {', '\tif false {', R_CL)
m(AL, 'ad, err := agents.Domains(agent, c.env.OpencodeBaseURL)', 'ad, err := agents.Domains(agent, "")', R_CL)
m(AL, '\tfull := stringsUnique(append(append([]string(nil), cur...), add...))', '\tfull := append(append([]string(nil), cur...), add...)', R_CL)
m(AL, '\textras := stringsMinus(full, ad, tier.Domains(tierV))', '\textras := stringsMinus(full, ad)', R_CL)
m(AL, '\tadded := len(stringsMinus(stringsUnique(add), stringsUnique(cur)))', '\tadded := len(stringsMinus(add, cur))', R_CL)
m(AL, '\tif added == 0 {', '\tif added < 0 {', R_CL)
m(AL, 'jqInterp(d.Get("resource_name"))+" "+jqInterp(d.Get("port")))', 'jqInterp(d.Get("resource_name")))', R_CL)
m(AL, 'KubeHostEntity: jqRawField(rec, "kube_host_entity", ""),', 'KubeHostEntity: "",', R_CL)
m(AL, '\taudit.SetField(logDir, "allowed_domains", fv)', '', R_CL)
m(AL, 'strings.Join(add, ",")', 'strings.Join(stringsUnique(add), ",")', R_CL)
m(AL, 'c.out("  Full allowed-domain count: %d", len(full))', 'c.out("  Full allowed-domain count: %d", len(cur))', R_CL)
m(AL, '\t\tif i == 0 || x != s[i-1] {', '\t\tif true {', R_CL)
m(AL, '\t\tif !drop[x] {', '\t\tif true {', R_CL)
m(AL, '\t\tc.errOut("jq: error (at <unknown>): Cannot iterate over null (null)")\n\t\tpanic(exit(5))', '', R_CL)
m(AL, '\tif v.Kind == jqjson.String {\n\t\treturn v.Str\n\t}\n\treturn strings.TrimSuffix', '\treturn strings.TrimSuffix', R_CL)

m(RP, '\t\tc.maskTypeCheck(s.Repos)\n', '', R_CL)
m(RP, '\tif len(all) == 0 {\n\t\treturn\n\t}\n\twhy', '\tif len(all) <= 1 {\n\t\treturn\n\t}\n\twhy', R_CL)
m(RP, '\t\twhy = "(the mask would not cover them):"', '\t\twhy = "(would crash gVisor at container start):"', "TestFixMaskMismatchNoGVisor")
m(RP, '\tfmt.Fprint(c.stderr, "\\n  Either remove these paths or convert them to the expected type.\\n \\n")\n\tpanic(exit(1))', '\tfmt.Fprint(c.stderr, "\\n  Either remove these paths or convert them to the expected type.\\n \\n")', R_CL)
m(RP, '\t\t} else if h := urlHost(ep); h != "" {', '\t\t} else if h := urlHost(ep); true {', "TestFixInfraEndpointHost")
m(RP, '\t\t\tout = append(out, h)', '\t\t\tout = append(out, ep)', "TestFixInfraEndpointHost")
m(RP, '\t\t\tout = append(out, ep)\n\t\t} else', '\t\t\tout = append(out, urlHost(ep))\n\t\t} else', R_CL)
RS = "internal/cli/resume.go"
m(RS, '\t\tc.maskTypeCheck(repos)\n', '', R_CL)
m(RS, '\t\tcase sessionID == "":\n\t\t\tsessionID = a\n\t\tdefault:', '\t\tcase true:\n\t\t\tsessionID = a\n\t\tdefault:', R_CL)
m(RS, '\tif sessionID == "" {\n\t\tc.die("Usage: sandbox resume', '\tif false {\n\t\tc.die("Usage: sandbox resume', R_CL)
m(RS, '\tif !config.IsFile(sj) {\n\t\tc.die("Session not found', '\tif false {\n\t\tc.die("Session not found', R_CL)
m(RS, '\tpod := jqAlt(sj, "pod_name", "")\n\tif pod == "" {\n\t\tpod = "sandbox-" + sessionID\n\t}\n\tif !config', '\tpod := jqAlt(sj, "pod_name", "")\n\tif !config', R_CL)
m(RS, '\t} else if phase != "Running" {', '\t} else if false {', R_CL)
m(RS, '\tcase bashcompat.ArithCmp(tierV, "3", "eq"):\n\t\treturn "tier 3 infra credentials are never persisted"', '\tcase false:\n\t\treturn "tier 3 infra credentials are never persisted"', R_CL)
m(RS, '\tcase bashcompat.ArithCmp(tierV, "3", "eq"):\n\t\treturn "tier 3\'s --infra-token', '\tcase false:\n\t\treturn "tier 3\'s --infra-token', "TestResumeOnSandboxd")
m(RS, '\tcase profile != "":', '\tcase false:', R_CL)
m(RS, '\tcase agent == "opencode":\n\t\treturn "opencode reads', '\tcase false:\n\t\treturn "opencode reads', R_CL)
m(RS, '\tif profile != "" {\n\t\tcmd += " --profile " + profile', '\tif false {\n\t\tcmd += " --profile " + profile', R_CL)
m(RS, '\t\tcmd += " --name \'" + name + "\'"', '\t\tcmd += " --name " + name', R_CL)
m(RS, '\tfor _, d := range c.resumeExtras(rec, agent, tierV) {', '\tfor _, d := range jqLines(rec.Get("allowed_domains")) {', R_CL)
m(RS, 'return stringsMinus(jqLines(rec.Get("allowed_domains")), ad, tier.Domains(tierV))', 'return stringsMinus(jqLines(rec.Get("allowed_domains")), ad)', R_CL)
m(RS, '\tif tierAtLeast(tierV, "2") && len(repos) > 0 {', '\tif tierAtLeast(tierV, "3") && len(repos) > 0 {', R_CL)
m(RS, '\t\t\tfor _, l := range workspace.Prescan(r) {', '\t\t\tfor _, l := range workspace.Prescan(r)[:0] {', R_CL)
m(RS, 'vs, ss, _ := c.workspaceGates(agent, c.env.OpencodeBaseURL, repos, acceptUnmasked, acceptUnvetted, acceptDrift, &overrides)', 'vs, ss, _ := c.workspaceGates(agent, c.env.OpencodeBaseURL, repos, acceptUnmasked, acceptUnvetted, acceptUnvetted, &overrides)', R_CL)
m(RS, '\t\t\taudit.LogEvent(logDir, "secret-scan", ss, c.stamp())', '', R_CL)
m(RS, '\t\taudit.FlushOverrides(logDir, overrides, c.stamp())', '', R_CL)
m(RS, 'user := jqRawField(rec, "name", ""), jqRawField(rec, "user", "unknown")', 'user := jqRawField(rec, "name", ""), jqRawField(rec, "user", "")', R_CL)
m(RS, 'Image: "docker.io/library/sandbox:" + agent,', 'Image: "docker.io/library/sandbox:claude",', R_CL)
m(RS, 'cmd = append(cmd, strings.Fields(agents.SandboxFlags(agent))...)', 'cmd = append(cmd)', R_CL)
m(RS, 'agentSessionID != "" && rf != "" {', 'rf != "" {', R_CL)
m(RS, 'c.out("    Agent: %s  |  Log: %s", agent, c.tilde(logDir))', 'c.out("    Agent: %s  |  Log: %s", agent, logDir)', R_CL)
m(RS, 'KeepAlive: keepAlive})', 'KeepAlive: false})', R_CL)
m(RS, '\t\t\tif x.Kind == jqjson.Null || !x.B {', '\t\t\tif x.Kind == jqjson.Null {', R_CL)

SE = "internal/secrets/secrets.go"
m(SE, '\tcase name == "":\n\t\treturn fail("ERROR: secret name is empty.")', '\tcase false:\n\t\treturn fail("ERROR: secret name is empty.")', R_CL,
  equivalent="the CLI refuses an empty name with its usage line before validating")
m(SE, '\tcase len(name) > 64:', '\tcase len(name) > 65:', R_CL)
m(SE, '\tcase !nameRe.MatchString(name):', '\tcase false:', R_CL)
m(SE, '\tos.Chmod(s.Dir, 0o700)', '', R_CL)
m(SE, '\tf, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)', '\tf, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0o600)', R_CL)
m(SE, '\tos.Chmod(path, 0o600)\n\treturn nil', '\treturn nil', R_CL)
m(SE, '\tif st, err := os.Stat(src); err != nil || !st.Mode().IsRegular() {', '\tif _, err := os.Stat(src); err != nil {', R_CL)
m(SE, '\tif envVar == "" {', '\tif false {', R_CL,
  equivalent="an empty --from-env= reads stdin in the CLI, so the store never sees an empty name")
m(SE, '\tif v == "" {\n\t\treturn fail(fmt.Sprintf("ERROR: env var', '\tif false {\n\t\treturn fail(fmt.Sprintf("ERROR: env var', R_CL)
m(SE, '\t\tif !strings.HasPrefix(e.Name(), ".") {', '\t\tif true {', R_CL)
m(SE, '\tsort.Strings(names)\n', '\t_ = sort.Strings\n', R_CL,
  equivalent="os.ReadDir already returns names sorted bytewise")
m(SE, '\t\tif st, err := os.Stat(p); err != nil || !st.Mode().IsRegular() {\n\t\t\tcontinue', '\t\tif _, err := os.Stat(p); err != nil {\n\t\t\tcontinue', R_CL)
m(SE, '\t\t\tmtime = st.ModTime().In(loc).Format("2006-01-02 15:04:05")', '\t\t\tmtime = st.ModTime().UTC().Format("2006-01-02 15:04:05")', R_CL)
m(SE, '\t\tif len(pad) < 32 {', '\t\tif len([]rune(pad)) < 32 {', R_CL)
m(SE, '\tst, err := os.Stat(s.Path(name))\n\treturn err == nil && st.Mode().IsRegular()', '\t_, err := os.Lstat(s.Path(name))\n\treturn err == nil', R_CL)

SCM = "internal/secretcmd/secretcmd.go"
m(SCM, '\t\t\t\tif i+1 >= len(args) || args[i+1] == "" {', '\t\t\t\tif i+1 >= len(args) {', R_CL, pkg="cli")
m(SCM, '\t\t\tif strings.HasPrefix(src, "~") {', '\t\t\tif false {', R_CL, pkg="cli")
m(SCM, 'c.out("Stored secret \'%s\' from %s.", name, fromFile)', 'c.out("Stored secret \'%s\' from %s.", name, src)', R_CL, pkg="cli")
m(SCM, '\t\tif fromFile != "" && fromEnv != "" {', '\t\tif false {', R_CL, pkg="cli")
m(SCM, '\t\t\tif fromEnv == "_USE_DEFAULT" {', '\t\t\tif fromEnv == "" {', R_CL, pkg="cli")
m(SCM, '\t\t\tif !envName.MatchString(fromEnv) {', '\t\t\tif false {', R_CL, pkg="cli")
m(SCM, '\t\t\tif i == 0 {\n\t\t\t\tc.out("%-32s', '\t\t\tif i == 1 {\n\t\t\t\tc.out("%-32s', R_CL, pkg="cli")
m(SCM, 'c.out("No secrets in %s/.", c.tilde(c.env.Dir))', 'c.out("No secrets in %s/.", c.env.Dir)', R_CL, pkg="cli")
m(SCM, '\t\tif st.Exists(name) {', '\t\tif true {', R_CL, pkg="cli")
m(SCM, '\tcase "delete", "rm", "remove":', '\tcase "delete", "rm":', R_CL, pkg="cli")
m(SCM, '\t\tif err := secrets.ValidateName(name); err != nil {\n\t\t\tc.fail(err)\n\t\t}\n\t\tif fromFile', '\t\tif fromFile', R_CL, pkg="cli")

OBC = "internal/cli/onboard.go"
m(OBC, '\t\tcase a == "--skip-config":\n\t\t\tskipConfig = true', '\t\tcase a == "--skip-config":', R_CL)
m(OBC, '\tcase "claude", "codex", "opencode", "copilot", "grok", "all":', '\tcase "claude", "codex", "opencode", "copilot", "grok", "all", "":', R_CL)
m(OBC, '\tif n > 0 {\n\t\tc.out("")', '\tif n > 1 {\n\t\tc.out("")', R_CL)
m(OBC, 'list = []string{"claude", "codex", "opencode", "copilot", "grok"}', 'list = []string{"claude", "codex"}', R_CL)
m(OBC, 'DryRun: dry, Force: force}', 'DryRun: dry, Force: false}', R_CL)
m(OBC, '\tif dry {\n\t\tc.out("Dry-run complete', '\tif false {\n\t\tc.out("Dry-run complete', R_CL)

AW = "internal/allowlist/allowlist.go"
R_AW = "TestAllowlistGolden"
m(AW, '\tn := len(all) // the bash', '\tn := len(agentDomains) // the bash', R_AW)
m(AW, '\t\tif !strings.HasPrefix(d, "*.") {', '\t\tif !strings.HasPrefix(d, "*") {', R_AW)
m(AW, '\t\tapex := checks.NormalizeDomain(d[2:])', '\t\tapex := d[2:]', R_AW)
m(AW, '\t\tif checks.ApexIsRegistrableDomain(apex) && !c.DomainIsBlocked(apex) {', '\t\tif checks.ApexIsRegistrableDomain(apex) {', R_AW)
m(AW, '\t\tif checks.ApexIsRegistrableDomain(apex) && !c.DomainIsBlocked(apex) {', '\t\tif !c.DomainIsBlocked(apex) {', R_AW)
m(AW, '\t\tlines = append(lines, strings.Split(d, "\\n")...)', '\t\tlines = append(lines, d)', R_AW)
m(AW, '\t\tif strings.Trim(l, " \\t") == "" || seen[l] {', '\t\tif l == "" || seen[l] {', R_AW)
m(AW, '\t\tif strings.Trim(l, " \\t") == "" || seen[l] {', '\t\tif strings.Trim(l, " \\t") == "" {', R_AW)
m(AW, 'all := append(append(append([]string(nil), agentDomains...), tierDomains...), extras...)', 'all := append(append(append([]string(nil), agentDomains...), extras...), tierDomains...)', R_AW)

m(RP, '\tif t, _ := strconv.Atoi(s.Tier); t >= 2 && len(s.Repos) > 0 {\n\t\tc.out("==> Capturing', '\tif t, _ := strconv.Atoi(s.Tier); t >= 3 && len(s.Repos) > 0 {\n\t\tc.out("==> Capturing', R_CL)
m(RP, 'workspace.CaptureBaseline(rec.LogDir, s.Repos, workspace.PruneDirs(c.env.SandboxRoot))', 'workspace.CaptureBaseline(rec.LogDir, s.Repos, nil)', R_CL)
m(RP, '\tif s.Tier == "3" {\n\t\timage += "-infra"', '\tif s.Tier == "2" {\n\t\timage += "-infra"', R_CL)
m(RP, 'Extras: append(infraPolicyNames(s.InfraEndpoints), s.Domains...)}', 'Extras: append([]string{}, s.Domains...)}', R_CL)

BL = "internal/workspace/baseline.go"
R_BL = "TestBaselineGolden"
m(BL, '\t\tif in && pruneEnd.MatchString(l) {\n\t\t\tin = false', '\t\tif false {\n\t\t\tin = false', R_BL)
m(BL, '\t\t\tl = pruneCmt.ReplaceAllString(l, "")', '', R_BL)
m(BL, '\t\t\tif strings.HasPrefix(l, `"`) || strings.HasPrefix(l, "\'") {', '\t\t\tif strings.HasPrefix(l, `"`) {', R_BL)
m(BL, r'pruneItem  = regexp.MustCompile(`^[ \t\n\v\f\r]*-[ \t\n\v\f\r]`)', r'pruneItem  = regexp.MustCompile(`^[ \t\n\v\f\r]*-`)', R_BL)
m(BL, '\tif strings.ContainsAny(name, "\\\\\\n\\r") {', '\tif strings.ContainsAny(name, "\\\\\\n") {', R_BL)
m(BL, '\t\t} else if bashcompat.Glob(objects, path) {', '\t\t} else if path == objects {', R_BL)
m(BL, '\t\t\tif bashcompat.Glob(d, base) {', '\t\t\tif d == base {', R_BL)
m(BL, '\t\tcase st.Mode().IsRegular():', '\t\tcase !st.IsDir():', R_BL)
m(BL, '\t\t\tif err == nil {\n\t\t\t\tlines = append(lines, sumLine(', '\t\t\tif true {\n\t\t\t\tlines = append(lines, sumLine(', R_BL,
  equivalent="needs a file that opens but fails mid-read (an I/O error), which the corpus cannot make")
m(BL, '\t\t\t\tif strings.HasSuffix(path, "/") {\n\t\t\t\t\tsep = ""', '\t\t\t\tif false {\n\t\t\t\t\tsep = ""', R_BL)
m(BL, '\tsort.Strings(lines)\n\treturn lines', '\t_ = sort.Strings\n\treturn lines', R_BL)
m(BL, '\t\t\treturn []string{"  No baseline found; skipping diff."}', '\t\t\tb = nil', R_BL)
m(BL, '\tos.Remove(cur)', '', R_BL)
m(BL, '\t\tif strings.HasPrefix(l, "<") || strings.HasPrefix(l, ">") {', '\t\tif strings.HasPrefix(l, "<") {', R_BL)
m(BL, '\t\tcount += "\\n0"', '', R_BL)
m(BL, '\t\tcase i > di && j > dj:\n\t\t\tout = append(out, rng(di+1, i)+"c"+rng(dj+1, j))', '\t\tcase false:\n\t\t\tout = append(out, rng(di+1, i)+"c"+rng(dj+1, j))', R_BL)
m(BL, 'out = append(out, rng(di+1, i)+"d"+fmt.Sprint(j))', 'out = append(out, rng(di+1, i)+"d"+fmt.Sprint(j+1))', R_BL)
m(BL, 'out = append(out, fmt.Sprint(i)+"a"+rng(dj+1, j))', 'out = append(out, fmt.Sprint(i+1)+"a"+rng(dj+1, j))', R_BL)
m(BL, '\t\tif lo == hi {\n\t\t\treturn fmt.Sprint(lo)', '\t\tif false {\n\t\t\treturn fmt.Sprint(lo)', R_BL)
m(BL, '\t\tif i > di && j > dj {\n\t\t\tout = append(out, "---")', '\t\tif i > di {\n\t\t\tout = append(out, "---")', R_BL)
m(BL, 'return fmt.Sprintf("  Baseline: %d files.", len(all))', 'return fmt.Sprintf("  Baseline: %d files.", len(all)-1)', R_BL)
m(BL, '\t\tif i == di && j == dj { // not one shared order after all: take a[i] as removed\n\t\t\ti++\n\t\t}', '', R_BL,
  equivalent="a guard: the two lists always share one order, so it never fires (without it a broken order would loop forever)")

MO = "internal/mounts/mounts.go"
R_MO = "TestMountsGolden"
m(MO, '{".vscode", true}, {".idea", true}', '{".vscode", true}, {".idea", false}', R_MO)
m(MO, 'func isFile(p string) bool { st, err := os.Stat(p); return err == nil && st.Mode().IsRegular() }', 'func isFile(p string) bool { st, err := os.Lstat(p); return err == nil && st.Mode().IsRegular() }', R_MO)
m(MO, 'func isDir(p string) bool  { st, err := os.Stat(p); return err == nil && st.IsDir() }', 'func isDir(p string) bool  { st, err := os.Lstat(p); return err == nil && st.IsDir() }', R_MO)
m(MO, '\t\tif e.Type().IsRegular() && bashcompat.Glob(gate.MaskedOpenrcPattern, e.Name()) {', '\t\tif bashcompat.Glob(gate.MaskedOpenrcPattern, e.Name()) {', R_MO)
m(MO, '\tsort.Strings(out)\n\treturn out\n}', '\t_ = sort.Strings\n\treturn out\n}', R_MO,
  equivalent="os.ReadDir already returns names sorted bytewise")
m(MO, '\t\tcase mp == "":\n', '', R_MO,
  equivalent="an empty entry would test the repo directory itself as a file, which is never one")
m(MO, '\t\tcase strings.HasSuffix(mp, "/"):', '\t\tcase false:', R_MO)
m(MO, 'Kind: MaskDir, Index: idx})', 'Kind: MaskDir, Index: idx + 1})', R_MO)
m(MO, '\tif isDir(repo + "/" + gate.MaskedDirPath) {', '\tif isFile(repo + "/" + gate.MaskedDirPath) {', R_MO)
m(MO, '\t\tcase !p.Dir && isFile(full):', '\t\tcase !p.Dir && isDir(full):', R_MO)
m(MO, '\t\tcase p.Dir && isDir(full):', '\t\tcase p.Dir:', R_MO)
m(MO, '\tif isFile(repo + "/.git") {', '\tif isDir(repo + "/.git") {', R_MO)
m(MO, 'Kind: ReadonlyFile, Index: len(ReadonlyPaths)})', 'Kind: ReadonlyFile, Index: len(ReadonlyPaths) - 1})', R_MO)
m(MO, '\tif total == 1 {\n\t\treturn "/workspace"', '\tif total <= 2 {\n\t\treturn "/workspace"', R_MO)
m(MO, '\tfor _, p := range gate.MaskedFilePaths {\n\t\tif isFile(', '\tfor _, p := range gate.MaskedFilePaths[1:] {\n\t\tif isFile(', R_MO)
# the type check of check_masking_paths (Mismatches)
m(MO, '\tfor _, p := range gate.MaskedFilePaths {\n\t\tif full', '\tfor _, p := range gate.MaskedFilePaths[1:] {\n\t\tif full', R_MO)
m(MO, '\t\tif full := repo + "/" + p; exists(full) {', '\t\tif full := repo + "/" + p; isDir(full) {', R_MO)
m(MO, '\tif full := repo + "/" + gate.MaskedDirPath; exists(full) {\n\t\tcheck(full, "directory")', '\tif full := repo + "/" + gate.MaskedDirPath; isFile(full) {\n\t\tcheck(full, "directory")', R_MO)
m(MO, '\tif bashcompat.Glob(gate.MaskedOpenrcPattern, bashcompat.Basename(repo)) && exists(repo) {', '\tif false {', R_MO)
m(MO, '\t\t\tsep = "" // find joins "dir/" and "x" as "dir/x"\n\t\t}\n\t\tfor _, e := range ents {', '\t\t}\n\t\tfor _, e := range ents {', R_MO)
m(MO, '\t\t\t\tcheck(repo+sep+e.Name(), "file")', '\t\t\t\tif exists(repo + sep + e.Name()) {\n\t\t\t\t\tcheck(repo+sep+e.Name(), "file")\n\t\t\t\t}', R_MO)
m(MO, '\t\t\twant, bare = "directory", strings.TrimSuffix(rel, "/")', '\t\t\twant, bare = "directory", strings.TrimRight(rel, "/")', R_MO)
m(MO, '\t\tok := isFile(full)\n\t\tif want == "directory" {', '\t\tok := isFile(full)\n\t\tif want != "file" {', R_MO,
  equivalent="want is only ever file or directory")
m(MO, '\tif st, err := os.Lstat(p); err == nil && st.Mode()&os.ModeSymlink != 0 {', '\tif st, err := os.Stat(p); err == nil && st.Mode()&os.ModeSymlink != 0 {', R_MO)
m(MO, '\tcase isDir(p):\n\t\treturn "directory"\n\tcase isFile(p):\n\t\treturn "file"', '\tcase isFile(p):\n\t\treturn "file"\n\tcase isDir(p):\n\t\treturn "directory"', R_MO,
  equivalent="a path is never both a directory and a regular file")
m(MO, '\t\tif rel == "" {\n\t\t\tcontinue', '\t\tif rel == "-" {\n\t\t\tcontinue', R_MO,
  equivalent="LoadRepoMaskedPaths never returns an empty entry (the \"  -\" case in the corpus shows it)")

# ---- host: setup-proxy-cert (internal/host/proxycert)
PS = "internal/host/proxycert/subject.go"
PX = "internal/host/proxycert/extract.go"
R_PS = "TestOneLineGolden"
R_PX = "TestLinuxStoreGolden|TestMacAndWindows"
m(PS, '\t\tcase c > 0x7f || c < 0x20 || c == 0x7f:', '\t\tcase c > 0x7f || c < 0x20:', R_PS)
m(PS, "\t\tcase c == '\\\\' || c == '\"':", "\t\tcase c == '\\\\':", R_PS)
m(PS, '\t\tcase strings.IndexByte(`,+<>;`, c) >= 0:', '\t\tcase strings.IndexByte(`,+<>`, c) >= 0:', R_PS)
m(PS, "\t\tcase (c == ' ' || c == '#') && i == 0, c == ' ' && i == len(b)-1:", "\t\tcase (c == ' ' || c == '#') && i == 0:", R_PS)
m(PS, '\treturn strings.Join(rdns, ", "), nil', '\treturn strings.Join(rdns, ","), nil', R_PS)
m(PS, '\t\trdns = append(rdns, strings.Join(atvs, " + "))', '\t\trdns = append(rdns, strings.Join(atvs, ", "))', R_PS)
m(PS, '\t\t\tu[i] = uint16(b[2*i])<<8 | uint16(b[2*i+1])', '\t\t\tu[i] = uint16(b[2*i+1])<<8 | uint16(b[2*i])', R_PS)
m(PS, '"0.9.2342.19200300.100.1.25": "DC"', '"0.9.2342.19200300.100.1.25": "dc"', R_PS)
m(PX, '\t\tif subj != "" && m.MatchString(subj) {', '\t\tif m.MatchString(subj) {', R_PX,
  equivalent="no vendor pattern matches the empty string")
m(PX, '\tif ok {\n\t\treturn out, true\n\t}\n\tif st', '\tif st', R_PX)
m(PX, '\t\tif blk.Type != "CERTIFICATE" && blk.Type != "X509 CERTIFICATE" && blk.Type != "TRUSTED CERTIFICATE" {', '\t\tif blk.Type != "CERTIFICATE" && blk.Type != "TRUSTED CERTIFICATE" {', R_PX)
m(PX, '\treturn parseFirst(b)\n}', '\treturn nil\n}', R_PX)
m(PX, '\t\tif !strings.HasPrefix(filepath.Base(p), ".") {', '\t\tif true {', R_PX)
m(PX, '\tif len(lines) > 0 && lines[len(lines)-1] == "" {', '\tif false {', R_PX)
m(PX, '\t\tif strings.Contains(l, "-----BEGIN CERTIFICATE-----") {', '\t\tif strings.HasPrefix(l, "-----BEGIN CERTIFICATE-----") {', R_PX)
m(PX, '\tq := make([]string, len(v))\n\tfor i, s := range v {\n\t\tq[i] = regexp.QuoteMeta(s)', '\tq := make([]string, len(v))\n\tfor i, s := range v {\n\t\tq[i] = s', R_PX)

# ---- L7 rules (internal/l7): path globs, query conditions, deny-first decisions
L7 = "internal/l7/l7.go"
R_L7 = "."
m(L7, '\tif r.Host == AnyHost && r.Action != Deny {', '\tif false {', R_L7)
m(L7, '\t\tif len(c.Query) > 0 && r.Action != Deny {', '\t\tif false {', R_L7)
m(L7, '\t\tb.WriteString("|%")', '\t\tb.WriteString("|%%")', R_L7)
m(L7, "\t\t\tif h >= 'A' {\n\t\t\t\tb.WriteString(\"[\" + string(h) + string(h+'a'-'A') + \"]\")", "\t\t\tif h >= 'A' {\n\t\t\t\tb.WriteString(string(h))", R_L7)
m(L7, '|| strings.Contains(path, "//") {', '{', R_L7)
m(L7, '\t\t\tre.WriteString("(?:/.*)?")', '\t\t\tre.WriteString("/.*")', R_L7)
m(L7, '\t\t\t\tre.WriteString("[^/]*")', '\t\t\t\tre.WriteString(".*")', R_L7)
m(L7, '\t\t\tre.WriteString(regexp.QuoteMeta(part))', '\t\t\tre.WriteString(part)', R_L7)
m(L7, '\tre.WriteString("$")', '\tre.WriteString("")', R_L7)
m(L7, '|| seen[name] ||', '||', R_L7)
m(L7, '\t\t\t\t\t\tv.WriteString("[^&]*")', '\t\t\t\t\t\tv.WriteString(".*")', R_L7)
m(L7, '\t\t\t\tif strings.Trim(value, "*") == "" {', '\t\t\t\tif false {', R_L7)
m(L7, '`^(?:.*&)?` + cond + `(?:&.*)?$`', '`^(?:.*&)?` + cond', R_L7)
m(L7, '`^(?:.*&)?` + cond + `(?:&.*)?$`', '`(?:.*&)?` + cond + `(?:&.*)?$`', R_L7)
m(L7, '\t\tif r.Action == Deny && HostMatches(r.Host, host) && r.matches(method, path, rawQuery) {', '\t\tif r.Action == Deny && r.matches(method, path, rawQuery) {', R_L7)
m(L7, '\treturn !hasAllow, -1', '\treturn true, -1', R_L7)
m(L7, '\tif len(r.PathPatterns) == 0 {\n\t\treturn true\n\t}', '\tif len(r.PathPatterns) == 0 {\n\t\treturn false\n\t}', R_L7)

# ---- the credential broker's core (internal/gateway/broker)
BR = "internal/gateway/broker/broker.go"
SC = "internal/gateway/broker/scrub.go"
R_BR = "."
m(BR, '\tif h, port, ok := strings.Cut(host, ":"); ok && port == "443" {', '\tif h, _, ok := strings.Cut(host, ":"); ok {', R_BR, pkg="gateway/broker")
m(BR, '\tif lengths > 1 || (lengths > 0 && codings > 0) {', '\tif lengths > 1 {', R_BR, pkg="gateway/broker")
m(BR, '\t\tif strings.Contains(v, "%") {', '\t\tif false {', R_BR, pkg="gateway/broker")
m(BR, '\t\t\t\tif d, err := base64.StdEncoding.DecodeString(strings.TrimSpace(rest)); err == nil {\n\t\t\t\t\tnote(string(d))', '\t\t\t\tif d, err := base64.StdEncoding.DecodeString(strings.TrimSpace(rest)); err == nil {\n\t\t\t\t\t_ = d', R_BR, pkg="gateway/broker")
m(BR, '\t\tif !mine {', '\t\tif false {', R_BR, pkg="gateway/broker")
m(BR, '\t\tif !found[b.Placeholder] {', '\t\tif false {', R_BR, pkg="gateway/broker")
m(BR, '\t\tif len(vs) != 1 {\n\t\t\treturn nil, "", errAmbiguous\n\t\t}\n\t\tif rest, ok := cutFold(vs[0], "bearer "); !ok || strings.TrimSpace(rest) != b.Prefix+b.Placeholder {', '\t\tif len(vs) == 0 {\n\t\t\treturn nil, "", errAmbiguous\n\t\t}\n\t\tif rest, ok := cutFold(vs[0], "bearer "); !ok || strings.TrimSpace(rest) != b.Prefix+b.Placeholder {', R_BR, pkg="gateway/broker")
m(BR, '\t\tif hits != 1 {', '\t\tif hits == 0 {', R_BR, pkg="gateway/broker")
m(BR, '\t\tif !setting {', '\t\tif true {', R_BR, pkg="gateway/broker")
m(BR, '\tif len(v) >= 8 && !seen[v] {', '\tif !seen[v] {', R_BR,
  equivalent="every form of the test values is at least 8 bytes", pkg="gateway/broker")
m(BR, 'base64.StdEncoding.EncodeToString([]byte(b.Value)), base64.RawStdEncoding.EncodeToString([]byte(b.Value)),', 'base64.StdEncoding.EncodeToString([]byte(b.Value)),', R_BR, pkg="gateway/broker")
m(SC, '\t\tif !final && s.partial(buf[i:]) {', '\t\tif s.partial(buf[i:]) {', R_BR, pkg="gateway/broker")
m(SC, '\t\tif !final && s.partial(buf[i:]) {', '\t\tif false {', R_BR, pkg="gateway/broker")
m(SC, '\t\tif len(rest) < len(r.From) && bytes.HasPrefix(r.From, rest) {', '\t\tif len(rest) <= len(r.From) && bytes.HasPrefix(r.From, rest) {', R_BR, pkg="gateway/broker")
m(SC, '\t\tfor j := i; j > 0 && len(rs[j].From) > len(rs[j-1].From); j-- {', '\t\tfor j := i; j > 0 && len(rs[j].From) < len(rs[j-1].From); j-- {', R_BR, pkg="gateway/broker")

# ---- the gateway's SNI matcher (internal/gateway/envoyconf) and the multi-label wildcard
EC = "internal/gateway/envoyconf/envoyconf.go"
EM = "internal/egressmatch/egressmatch.go"
m(EC, '\t\treturn []obj{exact(p[2:]), suffix(p[1:])}', '\t\treturn []obj{suffix(p[1:])}', "TestChainMatcher", pkg="gateway/envoyconf")
m(EC, '\t\treturn []obj{exact(p[:len(p)-2]), prefix(p[:len(p)-1])}', '\t\treturn []obj{prefix(p[:len(p)-1])}', "TestChainMatcher", pkg="gateway/envoyconf")
m(EC, '{"not_matcher": exact("." + rest)}', '{"not_matcher": exact(rest)}', "TestChainMatcher",
  pkg="gateway/envoyconf")
m(EC, '`(?i)^[^.]+\\.` + regexp.QuoteMeta(rest) + "$"', '`(?i)^.+\\.` + regexp.QuoteMeta(rest) + "$"', "TestChainMatcher", pkg="gateway/envoyconf")
m(EM, '\t\treturn strings.HasSuffix(domain, "."+rest) && len(domain) > len(rest)+1', '\t\treturn strings.HasSuffix(domain, rest)', "TestAllowed", pkg="egressmatch")

# ---- the host half of the broker key (internal/host/brokerkey, internal/host/app/broker.go)
BK = "internal/host/brokerkey/brokerkey.go"
AB = "internal/host/app/broker.go"
m(BK, '\tif err != nil || subtle.ConstantTimeCompare(back, key) != 1 {', '\tif err != nil {', "TestGetChecksTheKeyStuck")
m(BK, '\tcase err == nil && len(key) == brokerseal.KeySize:', '\tcase err == nil:', "TestFile")
m(BK, '\tif permsOpen(st) {', '\tif false {', "TestFile")
m(BK, '\tif !st.Mode().IsRegular() {', '\tif false {', "TestFile")
m(BK, 'errors.As(err, &ee) && ee.ExitCode() == 44 {', 'errors.As(err, &ee) {', "TestKeychainToolFails")
m(AB, '\tv = bytes.TrimRight(v, "\\r\\n")\n\tif len(v) == 0 {', '\tif len(v) == 0 {', "TestBrokerPut", pkg="host/app")
AA = "internal/host/app/app.go"
m(AA, '\t\t\t\ta.warnBrokerKey(a.running())\n\t\t\t\tfmt.Fprintln(a.env.Stdout, "The sandbox VM is already running.")', '\t\t\t\tfmt.Fprintln(a.env.Stdout, "The sandbox VM is already running.")', "TestBrokerKeyPushedAtStart")
m(AB, '\tif err == nil && rc != 0 {', '\tif false {', "TestBrokerKeyPushedAtStart")
m(AB, '\tbrokerseal.Wipe(k)\n\tif err != nil {\n\t\ta.die("%v", err)\n\t}', '\tif err != nil {\n\t\ta.die("%v", err)\n\t}', "TestBrokerPut",
  equivalent="the wipe is not observable from the test; it limits how long the key stays in memory")

# ---- WebSocket frames through the broker (internal/gateway/broker/wsframe.go, extproc.go) and the
# upgrade route (internal/gateway/envoyconf/intercept.go)
WF = "internal/gateway/broker/wsframe.go"
EP = "internal/gateway/broker/extproc.go"
R_WF = "FrameScrubber|Process"
m(WF, '\tif b[1]&0x80 != 0 || b0&0x70 != 0 {', '\tif b[1]&0x80 != 0 {', R_WF, pkg="gateway/broker")
m(WF, '\tif b[1]&0x80 != 0 || b0&0x70 != 0 {', '\tif b0&0x70 != 0 {', R_WF, pkg="gateway/broker")
m(WF, '\t\t\t\tif !fin || n > 125 {', '\t\t\t\tif n > 125 {', R_WF, pkg="gateway/broker")
m(WF, '\t\t\t\tif !fin || n > 125 {', '\t\t\t\tif !fin || n > 126 {', R_WF, pkg="gateway/broker")
m(WF, '\t\t\t\tif f.msg != nil {\n\t\t\t\t\treturn nil, ErrUnframeable // a new message inside a fragmented one\n\t\t\t\t}', '', R_WF, pkg="gateway/broker")
m(WF, '\t\t\t\tif f.msg == nil {\n\t\t\t\t\treturn nil, ErrUnframeable\n\t\t\t\t}', '\t\t\t\tif f.msg == nil {\n\t\t\t\t\tf.msg, f.msgOp, f.started = NewScrubber(f.reps), opBin, true\n\t\t\t\t}', R_WF, pkg="gateway/broker")
m(WF, '\tif !f.started {', '\tif true {', R_WF, pkg="gateway/broker")
m(WF, '\t\tpiece = append(piece, f.msg.Close()...)\n', '', R_WF, pkg="gateway/broker")
m(WF, '\tif s.Hits > 0 && op == opClose && len(payload) >= 2 {', '\tif false {', R_WF, pkg="gateway/broker")
m(WF, '\tif len(p) > 125 {', '\tif len(p) > 126 {', R_WF, pkg="gateway/broker")
m(WF, '\tif f.inFrame || len(f.buf) > 0 {', '\tif f.inFrame {', R_WF, pkg="gateway/broker")
m(WF, '\t\tif n>>63 != 0 {', '\t\tif false {', R_WF, pkg="gateway/broker")
m(WF, '\tcase n < 126:\n\t\th = append(h, byte(n))', '\tcase n <= 126:\n\t\th = append(h, byte(n))', R_WF, pkg="gateway/broker")
m(WF, '\t\tif take > f.left {', '\t\tif take > f.left+1 {', R_WF, pkg="gateway/broker")
m(WF, '\t\tf.Hits += f.msg.Hits\n', '', R_WF, pkg="gateway/broker")
m(EP, '\t\t\t\t\tif h.Key == ":status" && headerValue(h) == "101" && !raw {', '\t\t\t\t\tif h.Key == ":status" && !raw {', R_WF, pkg="gateway/broker")
m(EP, '\t\t\t\t\tif frames != nil && h.Key == "sec-websocket-extensions" {', '\t\t\t\t\tif false {', R_WF, pkg="gateway/broker")
m(EP, '\t\t\t\tif err == nil && r.ResponseBody.GetEndOfStream() {', '\t\t\t\tif false {', R_WF, pkg="gateway/broker")
m(BR, '\t\tif h.Name == "upgrade" && !strings.EqualFold(v, "websocket") && !(strings.EqualFold(v, "SPDY/3.1") && allKube(bound)) {', '\t\tif false {', R_BR, pkg="gateway/broker")
m(BR, '\t\tif h.Name == "upgrade" && !strings.EqualFold(v, "websocket") && !(strings.EqualFold(v, "SPDY/3.1") && allKube(bound)) {', '\t\tif h.Name == "upgrade" && !strings.EqualFold(v, "websocket") && !strings.EqualFold(v, "SPDY/3.1") {', R_BR, pkg="gateway/broker")
m(BR, '&& (hb != "connection" || !upgrade) {', '{', R_BR, pkg="gateway/broker")
IC = "internal/gateway/envoyconf/intercept.go"
m(IC, '\t\treturn []obj{{"name": name, "match": um, "route": upgrade}, {"name": name, "match": match, "route": forward}}', '\t\treturn []obj{{"name": name, "match": match, "route": forward}}', "TestUpgradeCluster|TestEnvoyAccepts", pkg="gateway/envoyconf")
m(IC, '\t\tname, alpn = upgradeCluster, []string{"http/1.1"}', '\t\tname = upgradeCluster', "TestUpgradeCluster|TestEnvoyAccepts", pkg="gateway/envoyconf")

# ---- per-credential limits (internal/gateway/broker/limits.go) and their plumbing
LM = "internal/gateway/broker/limits.go"
R_LM = "Limit|Quota|Process"
m(LM, '\t\t\tif b.tokens > b.burst {', '\t\t\tif false {', R_LM, pkg="gateway/broker")
m(LM, '\t\tif b.quota > 0 && b.injected >= b.quota {', '\t\tif b.quota > 0 && b.injected > b.quota {', R_LM, pkg="gateway/broker")
m(LM, '\t\tif b.tokens < 1 {', '\t\tif b.tokens < 0 {', R_LM, pkg="gateway/broker")
m(LM, '\t\tl.buckets[r].tokens--\n', '', R_LM, pkg="gateway/broker")
m(LM, '\t\tl.buckets[r].injected++\n', '', R_LM, pkg="gateway/broker")
m(LM, '\t\tif rate == 0 {\n\t\t\trate = DefaultRatePerMinute\n\t\t}', '', R_LM, pkg="gateway/broker")
m(LM, '\t\tif burst == 0 {\n\t\t\tburst = DefaultBurst\n\t\t}', '', R_LM, pkg="gateway/broker")
m(LM, 'perSec: float64(rate) / 60,', 'perSec: float64(rate),', R_LM, pkg="gateway/broker")
m(BR, '\t\t\tif !slices.Contains(refs, b.Ref) {', '\t\t\tif true {', R_LM, pkg="gateway/broker")
m(BR, '\t\t\tif v < 0 || v > MaxLimit {', '\t\t\tif v < 0 {', R_LM, pkg="gateway/broker")
m(EP, '\t\t\t\tif o.TooMany {', '\t\t\t\tif false {', R_LM, pkg="gateway/broker")
m("internal/sessionspec/sessionspec.go", '\t\tif prev, ok := limits[b.Ref]; ok && prev != l {', '\t\tif false {', "TestValidateRefuses|TestBindingLimits")
m("internal/sessionspec/sessionspec.go", '\t\t\tif v < 0 || v > MaxLimit {', '\t\t\tif v > MaxLimit {', "TestValidateRefuses|TestBindingLimits")
m("internal/sandboxd/daemon/daemon.go", '\t\t\tRatePerMinute: b.RatePerMinute, Burst: b.Burst, Quota: b.Quota})', '\t\t})', "TestBrokerHandover", pkg="sandboxd/daemon")
m("internal/sandboxd/auditlog/sources.go", '"credential_rate_limited": true, ', '', ".", pkg="sandboxd/auditlog")

# ---- leaf renewal (internal/sandboxd/daemon/tls.go) and the watched SDS secret (envoyconf)
TL = "internal/sandboxd/daemon/tls.go"
R_TL = "LeafRenewal|RenewBefore|Interception"
m(TL, '\t\tif now.Before(sl.notAfter.Add(-d.renewBefore())) {', '\t\tif now.Before(sl.notAfter) {', R_TL, pkg="sandboxd/daemon")
m(TL, '\t\tsl.notAfter = now.Add(d.leafValidity())\n', '', R_TL, pkg="sandboxd/daemon")
m(TL, '\t\tsl.version++\n', '', R_TL, pkg="sandboxd/daemon")
m(TL, '\tif v := d.leafValidity() / 2; v < 48*time.Hour {', '\tif v := d.leafValidity() / 2; false {', R_TL, pkg="sandboxd/daemon")
m(TL, '\t\tif err != nil {\n\t\t\td.logf("session %s: renewing its leaves: %v", id, err)\n\t\t\tcontinue\n\t\t}\n\t\tsl.version++', '\t\tsl.version++', R_TL, pkg="sandboxd/daemon")
m("internal/sandboxd/daemon/daemon.go", '\td.renewLeaves(ctx, now)\n', '', R_TL, pkg="sandboxd/daemon")
m("internal/sandboxd/daemon/daemon.go", '\tdelete(d.leaves, id)\n', '', R_TL, pkg="sandboxd/daemon")
m(IC, '\t\t\t"watched_directory": obj{"path": path.Dir(ic.SDS)}},', '},', "TestSDSSecret", pkg="gateway/envoyconf")
m(IC, '\tif ic.SDS == "" {\n\t\tctx["tls_certificates"]', '\tif true {\n\t\tctx["tls_certificates"]', "TestSDSSecret", pkg="gateway/envoyconf")

# ---- attaching a terminal (internal/sandboxd/daemon/attach.go, server.go) and the lease
AT = "internal/sandboxd/daemon/attach.go"
SV = "internal/sandboxd/daemon/server.go"
R_AT = "Attach"
m(AT, '\t\tcase <-gone:\n\t\t\tgone = nil\n\t\t\tp.Kill(ctx, syscall.SIGHUP)', '\t\tcase <-gone:\n\t\t\tgone = nil', R_AT, pkg="sandboxd/daemon")
m(AT, '\t\t\tp.Resize(ctx, uint32(sz[0]), uint32(sz[1]))', '', R_AT, pkg="sandboxd/daemon")
m(AT, '\tif size[0] > 0 && size[1] > 0 {\n\t\tp.Resize(ctx, uint32(size[0]), uint32(size[1]))\n\t}', '', R_AT, pkg="sandboxd/daemon")
m(AT, '\t\t\tt.Attached, t.LastDetached, t.LastHeartbeat = false, now, now', '\t\t\tt.Attached, t.LastDetached = false, now', R_AT, pkg="sandboxd/daemon")
m(AT, '\t\tif d.attached[id] == 0 {', '\t\tif true {', R_AT, pkg="sandboxd/daemon")
m(AT, '\tt.Attached = true\n', '', R_AT, pkg="sandboxd/daemon")
m(SV, '\tif len(files) != 3 {', '\tif len(files) < 2 {', R_AT, pkg="sandboxd/daemon")
m(SV, '\t\tlimit.N = 1 << 62', '\t\tlimit.N = limit.N', R_AT, pkg="sandboxd/daemon",
  equivalent="the test's control messages fit in what is left of the request limit")
m("internal/sandboxd/limits/limits.go", '\tif t.Attached {\n\t\treturn false, ""\n\t}\n\tif grace', '\tif grace', "TestExpiry", pkg="sandboxd/limits")

# ---- the host's pre-pass before run (internal/cli/bindings.go, internal/host/app/runsecrets.go)
CB = "internal/cli/bindings.go"
R_CB = "TestRunBindings|TestRunSecretPresent"
m(CB, '\t\tif !seen[n] {', '\t\tif true {', R_CB)
m(CB, '\tcase c.prepass:\n\t\treturn true\n\tcase c.env.SecretPresent != nil:', '\tcase c.env.SecretPresent != nil:', R_CB)
m(CB, '\tcase c.env.SecretPresent != nil:', '\tcase false:', R_CB)
m(CB, '\t\tfor _, n := range d.Secrets {\n\t\t\tadd(n)\n\t\t}', '', R_CB)
m(CB, '\tif !depsOK {\n\t\treturn Prepass{}, false, 1\n\t}', '', R_CB)
m(RN, '\tif !c.prepass {\n\t\trunSyncs(c)\n\t}', '\trunSyncs(c)', R_CB + "|TestCLIGolden",
  equivalent="the test cases have no linked overlays or leakscan config to fetch, so the pre-pass's syncs change nothing observable")
HR = "internal/host/app/runsecrets.go"
R_HR = "TestRun|TestMirroredHome|TestRepoNamed"
m(HR, '\tif len(names) > maxBoundSecrets {', '\tif false {', R_HR, pkg="host/app")
m(HR, '\t\tif seen[n] {', '\t\tif false {', R_HR, pkg="host/app")
m(HR, '\t\tif !secretName.MatchString(n) {', '\t\tif false {', R_HR, pkg="host/app")
m(HR, '\tif _, err := dec.Token(); err != io.EOF {\n\t\treturn fail(', '\tif false {\n\t\treturn fail(', R_HR, pkg="host/app")
m(HR, '\tdec.DisallowUnknownFields()\n\tvar out struct {\n\t\tSecrets', '\tvar out struct {\n\t\tSecrets', R_HR, pkg="host/app")
m(HR, '\tif out.Secrets == nil || out.Repos == nil {', '\tif out.Secrets == nil {', R_HR, pkg="host/app")
m(HR, '\t\tif h.Name != "config.yaml" && !strings.HasPrefix(h.Name, "profiles/") {', '\t\tif h == nil {', R_HR, pkg="host/app")
m(HR, '\t\tif !m[n] {', '\t\tif false {', R_HR, pkg="host/app")
m(HR, '\t\treturn !(r == \'_\' ||', '\t\treturn !(', R_HR, pkg="host/app")
m(HR, '\t\twords([]byte(a), m)', '', R_HR, pkg="host/app")
m(HR, '\tif len(names) == 0 {\n\t\treturn\n\t}', '', R_HR, pkg="host/app")
m(HR, '\t\tif absent {', '\t\tif false {', R_HR, pkg="host/app")
m(HR, '\tv, err = io.ReadAll(io.LimitReader(f, MaxSecretSize+1))\n\tif err == nil && len(v) > MaxSecretSize {', '\tv, err = io.ReadAll(io.LimitReader(f, MaxSecretSize+1))\n\tif false {', R_HR, pkg="host/app")
m(AA, '\tif len(args) > 0 && args[0] == "run" {', '\tif len(args) > 0 {', R_HR, pkg="host/app")

# ---- readable secrets (internal/sandboxd/daemon/readable.go, cmd/sandboxd/broker.go, sessionspec)
RD = "internal/sandboxd/daemon/readable.go"
R_RD = "Readable|TestRefusals"
m(RD, '\tif d.Broker == nil || d.ReadableRoot == "" {', '\tif d.Broker == nil {', R_RD, pkg="sandboxd/daemon")
m(RD, '\t\treturn os.Mkdir(dir, 0o700)', '\t\treturn os.MkdirAll(dir, 0o700)', R_RD, pkg="sandboxd/daemon",
  equivalent="a session's id is new (the journal refuses a reused one), so its directory never exists before")
m(RD, '\treturn runtime.Mount{Source: dir, Target: sessionspec.ReadableDir, ReadOnly: true}, env, nil', '\treturn runtime.Mount{Source: dir, Target: sessionspec.ReadableDir}, env, nil', R_RD, pkg="sandboxd/daemon")
m(RD, '\t\td.audit(id, auditlog.Events, "secret_readable",', '\t\t_ = (', R_RD, pkg="sandboxd/daemon")
m(RD, '%s=${%s%%x}; export %s; ', '%s=${%s}; export %s; ', R_RD, pkg="sandboxd/daemon")
m(RD, '|| { echo', '; { echo', R_RD, pkg="sandboxd/daemon")
m(RD, '\treturn strings.Contains(s, Shell) && (', '\treturn (', R_RD, pkg="sandboxd/daemon")
m("internal/sandboxd/daemon/attach.go", '\tif len(readable) > 0 {\n\t\trun = readableWrap(readable, args)\n\t}', '', R_RD, pkg="sandboxd/daemon")
m("internal/sandboxd/daemon/attach.go", '\tif err != nil && len(readable) > 0 && noShell(err) {', '\tif false {', R_RD, pkg="sandboxd/daemon")
m("internal/sandboxd/daemon/daemon.go", '\t\tcase KindReadable:\n\t\t\terr = os.RemoveAll(d.readableDir(id))\n', '', R_RD, pkg="sandboxd/daemon")
m("internal/sandboxd/daemon/daemon.go", '\t\t\td.readable[id] = append(d.readable[id], r.EnvVar)', '', R_RD, pkg="sandboxd/daemon")
SB = "cmd/sandboxd/broker.go"
m(SB, '\treturn n != "" && n != "." && n != ".." && !strings.ContainsAny(n, "/\\x00")', '\treturn n != ""', "TestWriteReadable", pkg="../cmd/sandboxd")
m(SB, 'os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o400', 'os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o400', "TestWriteReadable", pkg="../cmd/sandboxd")
m(SB, '\treturn os.Chmod(job.Dir, 0o500)\n}\n\n// validFileName', '\treturn nil\n}\n\n// validFileName', "TestWriteReadable", pkg="../cmd/sandboxd")
m("internal/sessionspec/sessionspec.go", '\tif len(s.Readable) > MaxReadable {', '\tif false {', "TestValidateRefuses")
m("internal/sessionspec/sessionspec.go", '\t\tfor _, v := range []string{r.EnvVar, file} {', '\t\tfor _, v := range []string{r.EnvVar} {', "TestValidateRefuses")

# ---- run through sandboxd: the spec (internal/cli/runspec.go), the launch (runlaunch.go), the VM's
# images and workspace copies (cmd/sandbox-vm/launch.go)
RS = "internal/cli/runspec.go"
R_RS = "TestBuildSpec|TestQuantities|TestLaunch"
m(RS, '\t\tn <<= 10', '\t\tn <<= 0', R_RS)
m(RS, '\t\treturn float64(n) / 1000, nil', '\t\treturn float64(n), nil', R_RS)
m(RS, 'cpuQty = regexp.MustCompile(`^([0-9]+)(m?)$`)', 'cpuQty = regexp.MustCompile(`([0-9]+)(m?)`)', R_RS)
m(RS, '\tif len(pod) > 63 {', '\tif len(pod) > 64 {', R_RS)
m(RS, '\t\tpod = strings.TrimRight(pod[:63], "-")', '\t\tpod = pod[:63]', R_RS)
m(RS, '\t\tfor _, m := range append(mounts.Masks(i, copyDir), mounts.Readonly(i, copyDir)...) {', '\t\tfor _, m := range mounts.Readonly(i, copyDir) {', R_RS)
m(RS, '\t\tfor _, m := range append(mounts.Masks(i, copyDir), mounts.Readonly(i, copyDir)...) {', '\t\tfor _, m := range mounts.Masks(i, copyDir) {', R_RS)
m(RS, '\t\t\t\tspec.Mounts = append(spec.Mounts, sessionspec.Mount{Kind: sessionspec.ReadOnly, Source: copyDir + "/" + m.Rel, Target: t, ReadOnly: true})', '\t\t\t\tspec.Mounts = append(spec.Mounts, sessionspec.Mount{Kind: sessionspec.ReadOnly, Source: copyDir + "/" + m.Rel, Target: t})', R_RS)
m(RS, '\tif s.Agent == "claude" {\n\t\tspec.Env', '\tif false {\n\t\tspec.Env', R_RS)
m(RS, 'BlockDomains: chk.BlockedDomains(), BlockCIDRs: chk.BlockedCIDRs()}\n\n', 'BlockCIDRs: chk.BlockedCIDRs()}\n\n', R_RS)
m(RS, '\tif s.Profile != "" {\n\t\tspec.Audit["profile"]', '\tif false {\n\t\tspec.Audit["profile"]', R_RS)
RL = "internal/cli/runlaunch.go"
m(RL, '\tif s.KeepAlive {\n\t\tc.out("==> Disconnected from', '\tif false {\n\t\tc.out("==> Disconnected from', R_RS)
m(RL, '\tif s.DryRun {', '\tif false {', R_RS)
m(RL, '\tif err := l.Sessions.Start(spec); err != nil {', '\tif l.Sessions.Start(spec); false {', R_RS)
m(RL, '\tif sessionID != "" {\n\t\tcmd = append(cmd, agents.SessionIDFlag(agent), sessionID)', '\tif false {\n\t\tcmd = append(cmd, agents.SessionIDFlag(agent), sessionID)', R_RS)
m(RL, '\t\trt = sessionspec.RuntimeKata\n\t}\n\trow("Runtime", rt)', '\t\trt = "gvisor"\n\t}\n\trow("Runtime", rt)', R_RS)
m(RL, '\trow("Log", c.tilde(rec.LogDir))', '\trow("Log", rec.LogDir)', R_RS)
m(RL, '\tcase 0:\n\t\trow("Repo", "emptyDir (ephemeral)")', '\tcase 0:', R_RS)
VL = "cmd/sandbox-vm/launch.go"
m(VL, '`/[0-9a-f]{16}$`', '`/[0-9a-f]{16}`', "TestWorkspaceCopyOf", pkg="../cmd/sandbox-vm")
m(VL, '\t\tif err != nil || !workspaceCopy.MatchString(p) {', '\t\tif err != nil {', "TestWorkspaceCopyOf", pkg="../cmd/sandbox-vm")
m(VL, '\t\t\tif ref, ok := m[tag]; ok {', '\t\t\tif ref, ok := m[tag]; ok || true {', "TestAgentImage", pkg="../cmd/sandbox-vm")

# ---- the host half of run: mirrored paths, repository checks (host/app/runsecrets.go), and the
# VM's mirror (cmd/sandbox-vm/mirror.go)
m(HR, '\tif len(repos) > maxRepos {', '\tif false {', R_HR, pkg="host/app")
m(HR, "\t\tif !strings.HasPrefix(r, \"/\") || path.Clean(r) != r || r == \"/\" ||", "\t\tif !strings.HasPrefix(r, \"/\") || r == \"/\" ||", R_HR, pkg="host/app")
m(HR, '\t\tif seen["\\x00"+r] {', '\t\tif false {', R_HR, pkg="host/app")
m(HR, '\t\tif !repoNamed(r, args, texts, a.mirrorHome()) {', '\t\tif false {', R_HR, pkg="host/app")
m(HR, '\t\tif home != "" && (v == "~" || strings.HasPrefix(v, "~/")) {', '\t\tif false {', R_HR, pkg="host/app")
m(HR, '\t\tforms = append(forms, "~"+p[len(home):])', '', R_HR, pkg="host/app")
m(HR, '\t\tif v == "" || strings.HasPrefix(v, "/") || strings.HasPrefix(v, "~") {', '\t\tif v == "" || strings.HasPrefix(v, "/") {', R_HR, pkg="host/app")
m(HR, '\t\tcase strings.HasPrefix(a, "--repo="):\n\t\t\tout[i] = ', '\t\tcase false:\n\t\t\tout[i] = ', R_HR, pkg="host/app")
m(HR, '\tif h == "" || !strings.HasPrefix(h, "/") || path.Clean(h) != h || h == "/" {', '\tif h == "" {', R_HR, pkg="host/app")
m(AA, '\t\targv = append(argv, h) // the VM links', '\t\t_ = append(argv, h) // the VM links', R_HR, pkg="host/app")
MI = "cmd/sandbox-vm/mirror.go"
m(MI, '\tif len(parts) < 3 {', '\tif len(parts) < 2 {', "TestMirror", pkg="../cmd/sandbox-vm")
m(MI, '\t\tif parts[1] == r {', '\t\tif false {', "TestMirror", pkg="../cmd/sandbox-vm")
m(MI, '\tif target != OperatorDir && !copyTarget.MatchString(target) {', '\tif false {', "TestMirror", pkg="../cmd/sandbox-vm")
m(MI, '\t\tcase !st.IsDir():', '\t\tcase false:', "TestMirror", pkg="../cmd/sandbox-vm")
m(MI, '&& cur == target {', '{', "TestMirror", pkg="../cmd/sandbox-vm")
m(MI, 'filepath.Clean(hostPath) != hostPath ||', '', "TestMirror", pkg="../cmd/sandbox-vm")
m(RN, '\t\tif c.prepass {\n\t\t\tbreak // the host', '\t\tif false {\n\t\t\tbreak // the host', R_CB)

# ---- end-to-end fixes: the sync state bound to the VM copy's epoch, the epoch read, protected git
m("internal/host/syncengine/engine.go", '\tif e.Copy != "" && s.Copy != e.Copy {', '\tif false {', "TestNewCopyKeepsHostFiles", pkg="host/syncengine")
m("internal/host/syncengine/engine.go", '\t\treturn fresh(), nil\n\t}\n\tif s.Base', '\t\treturn s, nil\n\t}\n\tif s.Base', "TestNewCopyKeepsHostFiles", pkg="host/syncengine")
m("internal/host/app/syncone.go", '\tif !epochRE.MatchString(e) {', '\tif false {', "TestCopyEpoch", pkg="host/app")
m("internal/host/app/syncone.go", '\t\tCopy:        epoch,\n', '\t\tCopy:        epoch[:0],\n', "TestCopyEpoch", pkg="host/app",
  equivalent="no host test drives a whole sync through the fake transport; the end-to-end run in the appliance checked it")
m("cmd/sandbox-vm/gitenv.go", ', {"core.hooksPath", "/dev/null"}', '', "TestProtectGit", pkg="../cmd/sandbox-vm")
m("cmd/sandbox-vm/gitenv.go", '\t\tn++\n', '', "TestProtectGit", pkg="../cmd/sandbox-vm")
m("internal/sandboxd/daemon/attach.go", 'return 0, errors.New("attach: " + firstLine(err))', 'return 0, fmt.Errorf("attach: %w", err)', "TestAttachErrorFirstLine", pkg="sandboxd/daemon")
m(AB, '\tfor i := 1; err != nil && transient(err) && i < keyPushTries; i++ {', '\tfor i := 1; err != nil && transient(err) && i < 1; i++ {', "TestBrokerKeyPushedAtStart", pkg="host/app")
m(AB, '\tfor i := 1; err != nil && transient(err) && i < keyPushTries; i++ {', '\tfor i := 1; err != nil && i < keyPushTries; i++ {', "TestBrokerKeyPushedAtStart", pkg="host/app")

# ---- workspace views (internal/sandboxd/daemon/views.go and mounts in daemon.go)
VW = "internal/sandboxd/daemon/views.go"
R_VW = "TestViews|TestStartAndStop"
m("internal/sandboxd/daemon/daemon.go", 'ok && !isDirOverlay(m) {', 'ok {', R_VW, pkg="sandboxd/daemon")
m("internal/sandboxd/daemon/daemon.go", '\tif m.Kind == sessionspec.MaskDir {\n\t\treturn true\n\t}', '', R_VW, pkg="sandboxd/daemon")
m("internal/sandboxd/daemon/daemon.go", '\t\t\t\tif err := d.Mounter.Over(v, rel, cover); err != nil && !errors.Is(err, ErrNoTarget) {', '\t\t\t\tif err := d.Mounter.Over(v, rel, cover); err != nil {', R_VW, pkg="sandboxd/daemon")
m("internal/sandboxd/daemon/daemon.go", '\t\tcase KindView:\n\t\t\terr = d.dropView(id, r.Name)\n', '', R_VW, pkg="sandboxd/daemon")
m("internal/sandboxd/daemon/daemon.go", '\t\t\t\tcover = src\n', '', R_VW, pkg="sandboxd/daemon")
m(VW, '\tif err := d.Mounter.Unmount(v); err != nil {\n\t\treturn err\n\t}\n', '', R_VW, pkg="sandboxd/daemon")
m(VW, '\tos.Remove(filepath.Dir(v)) // the views directory, once empty\n', '', R_VW, pkg="sandboxd/daemon")

# ---- stop and list on sandboxd (internal/cli/stop.go, sessions.go)
ST = "internal/cli/stop.go"
R_ST = "TestStop|TestListActive|TestLaunch"
m(ST, '\tcase !live:', '\tcase false:', R_ST)
m(ST, '\t\t\tendReason, endDetail = "teardown-incomplete", "sandboxd stop failed: "+firstErrLine(err)', '\t\t\t_ = endDetail', R_ST)
m(ST, '\tif hadToken {', '\tif false {', R_ST)
m(ST, '\t\taudit.UpdateEndTime(logDir, end)\n', '', R_ST)
m(ST, '\t\tif err := s.Stop(id, "operator stop"); err != nil {', '\t\tif err := s.Stop(id, "operator stop"); false && err != nil {', R_ST)
m("internal/cli/runlaunch.go", '\tc.stopSession(rec.ID)\n', '', R_ST)
m("internal/cli/sessions.go", '\tif len(live) == 0 {\n\t\treturn\n\t}', '', R_ST)
m("internal/cli/sessions.go", '"RUNNING": "Running",', '"RUNNING": "Pending",', R_ST)
m("internal/cli/sessions.go", 'tabwriter.NewWriter(c.stdout, 0, 8, 3,', 'tabwriter.NewWriter(c.stdout, 0, 8, 2,', R_ST)
m("internal/cli/resume.go", '\t\tif r.KeepAlive {\n\t\t\tc.out("==> Disconnected from', '\t\tif false {\n\t\t\tc.out("==> Disconnected from', "TestResumeOnSandboxd")
m("internal/cli/resume.go", '\t\t\tmcp = c.recreateOnSandboxd(sessionID, keepAlive, acceptUnmasked, acceptUnvetted, acceptDrift)', '\t\t\tc.recreateSession(sessionID, acceptUnmasked, acceptUnvetted, acceptDrift)', "TestResumeRecreates")
m("internal/cli/resume.go", '\t\tif !live {\n\t\t\treturn false, ""\n\t\t}', '', "TestResumeOnSandboxd")

# ---- the live sync during a run (internal/host/app/livesync.go, syncone.go)
m("internal/host/app/syncone.go", '\tif live != nil && live.Err() == nil {\n\tpasses:', '\tif false {\n\tpasses:', "TestLiveSync", pkg="host/app")
m("internal/host/app/syncone.go", 'if liveOn := live != nil && live.Err() == nil; !liveOn && tries >= syncTries {', 'if liveOn := live != nil && live.Err() == nil; !liveOn && tries >= 1 {', "TestLiveSync|TestSyncGivesUp", pkg="host/app")
m("internal/host/app/syncone.go", 'if liveOn := live != nil && live.Err() == nil; !liveOn && tries >= syncTries {', 'if liveOn := live != nil && live.Err() == nil; tries >= syncTries {', "TestLiveSync|TestSyncGivesUp", pkg="host/app")
m("internal/host/app/livesync.go", '\tl.toHost += len(rep.ToHost)', '\tl.toHost += 0', "TestLiveSync", pkg="host/app")
m("internal/host/app/app.go", '\t\tlive := a.startLiveSync(ep, prep.synced)\n\t\tdefer live.finish()\n', '\t\tlive := a.startLiveSync(ep, prep.synced)\n\t\t_ = live\n', "TestLiveSync|TestRun", pkg="host/app",
  equivalent="no host test drives a proxied run with repositories through a live sync")

# ---- the agent's memory default scaled to the VM (internal/sandboxd/limits, cli/runspec.go)
LM = "internal/sandboxd/limits/limits.go"
R_LM = "TestAgentMemory|TestMemTotalMiB"
m(LM, '\tn := b.VMMemoryMiB - b.reserve() - b.overhead()', '\tn := b.VMMemoryMiB - b.reserve()', R_LM, pkg="sandboxd/limits")
m(LM, '\t\tn -= d + b.overhead()', '\t\tn -= d', R_LM, pkg="sandboxd/limits")
m(LM, '\tn &^= 255\n', '', R_LM, pkg="sandboxd/limits")
m(LM, '\treturn max(min(n, AgentMaxMiB), AgentMinMiB)', '\treturn min(n, AgentMaxMiB)', R_LM, pkg="sandboxd/limits")
m(LM, '\t\t\treturn kb / 1024, err', '\t\t\treturn kb / 1000, err', R_LM, pkg="sandboxd/limits")
m(LM, 'fs[0] == "MemTotal:" {', 'strings.HasPrefix(fs[0], "Mem") {', R_LM, pkg="sandboxd/limits")
m("internal/cli/runspec.go", '\tif vm <= 0 {\n\t\treturn limits.AgentMaxMiB\n\t}', '', "TestAgentMemory|TestBuildSpec")
m("internal/cli/runspec.go", '\t\tmem = append(mem, d.Resources.MemoryMiB)', '', "TestAgentMemory")
m("internal/cli/runspec.go", '\tspec.Resources.MemoryMiB = agentMemory(in.VMMemoryMiB, spec.Dependencies)', '\tspec.Resources.MemoryMiB = agentMemory(0, spec.Dependencies)', "TestAgentMemory|TestBuildSpec|TestLaunch")
m("internal/cli/runlaunch.go", '\t\tif in.VMMemoryMiB, err = l.VMMemoryMiB(); err != nil {', '\t\tif _, err = l.VMMemoryMiB(); err != nil {', "TestLaunch")
m("internal/cli/runlaunch.go", '\t\t\tc.die("The VM\'s memory: %v", err)', '\t\t\t_ = err', "TestLaunch")

# ---- the gates' git unprivileged in the VM (cmd/sandbox-vm/gitenv.go, vetting.VerifyTag)
GE = "cmd/sandbox-vm/gitenv.go"
m(GE, '\tif euid != 0 || !exists(GateGitDir+"/git") {', '\tif !exists(GateGitDir+"/git") {', "TestDropGit", pkg="../cmd/sandbox-vm")
m(GE, '\tif euid != 0 || !exists(GateGitDir+"/git") {', '\tif euid != 0 {', "TestDropGit", pkg="../cmd/sandbox-vm")
m(GE, '\t\tpath += ":" + p', '\t\tpath = p', "TestDropGit", pkg="../cmd/sandbox-vm")
m(GE, '\tsetenv(trustedEnv, TrustedGit)\n', '', "TestDropGit", pkg="../cmd/sandbox-vm")
VT2 = "internal/vetting/verify.go"
R_VT2 = "TestVerifyTagIgnoresWorkspaceConfig|TestFixVerify"
m(VT2, '\targs := []string{"-C", scratch,', '\targs := []string{"-C", repo,', R_VT2)
m(VT2, '\tcmd := exec.Command(TrustedGit(), args...)', '\tcmd := exec.Command("git", args...)', R_VT2)
m(VT2, '\t\treturn p\n\t}\n\treturn "git"', '\t\treturn "git"\n\t}\n\treturn "git"', R_VT2)
m(VT2, '\tcat := VettingGit(repo, "cat-file", "tag", "refs/tags/"+tag)', '\tcat := VettingGit(repo, "cat-file", "-p", "refs/tags/"+tag)', R_VT2,
  equivalent="cat-file -p prints a tag object byte for byte, as cat-file tag does")
m(VT2, '\tdefer os.RemoveAll(scratch)\n', '', R_VT2,
  equivalent="a leftover temporary directory changes no result")
m(VT2, '\t\t\tif _, ok := git(nil, "update-ref", "refs/tags/"+tag, oid); ok {', '\t\t\tif _, ok := git(nil, "update-ref", "refs/tags/x", oid); ok {', R_VT2)

# ---- secret bindings (owner decision, ninth round): brokerseal's second form, the helpers'
# checks, the host store and command, the push, and run's spec
BS = "internal/brokerseal/brokerseal.go"
R_BS = "TestSealBound|TestBindingRules|TestSealOpen"
m(BS, '\treturn append([]byte("sandbox-broker-v2:"+ref+"\\x00"), binding...)', '\treturn []byte("sandbox-broker-v2:" + ref)', R_BS)
m(BS, '\tif enc, err := json.Marshal(b); err != nil || !bytes.Equal(enc, raw) {', '\tif _, err := json.Marshal(b); err != nil {', R_BS)
m(BS, '\tif err := b.Validate(); err != nil {\n\t\treturn Binding{}, nil, nil, err\n\t}', '', R_BS)
m(BS, '\tif n > maxBinding || len(rest) < n {', '\tif len(rest) < n {', R_BS)
m(BS, '\tcase b.Readable && (len(b.Hosts) > 0 || b.Inject != ""):', '\tcase false:', R_BS)
m(BS, '\tcase (len(b.Hosts) == 0) != (b.Inject == ""):', '\tcase len(b.Hosts) > 0 && b.Inject == "":', R_BS)
m(BS, '\t\tif i > 0 && h <= b.Hosts[i-1] {', '\t\tif i > 0 && h < b.Hosts[i-1] {', R_BS)
m(BS, '\t\tif !b.Readable {\n\t\t\treturn errors.New("the secret is not marked readable', '\t\tif false {\n\t\t\treturn errors.New("the secret is not marked readable', R_BS)
m(BS, '\tif len(hosts) == 0 || inject != b.Inject {', '\tif len(hosts) == 0 {', R_BS)
m(BS, '\t\tif !slices.Contains(b.Hosts, strings.ToLower(h)) {', '\t\tif !slices.Contains(b.Hosts, h) {', R_BS)
m(BS, '\tif len(h) > 253 || !strings.Contains(h, ".") {', '\tif len(h) > 253 {', R_BS)
m(BS, '\tslices.Sort(hs)\n', '', R_BS)
m(BS, '\t\treturn err == nil && len(body) >= 12+16', '\t\treturn err == nil', R_BS)
SB2 = "cmd/sandboxd/broker.go"
R_SB2 = "TestOpenLinks|TestWriteReadable"
m(SB2, '\t\t\tif _, secret := brokerseal.SecretName(u.Ref); secret && !bound {', '\t\t\tif false {', R_SB2, pkg="../cmd/sandboxd")
m(SB2, '\t\t\tif bound {\n\t\t\t\tif err := b.Allows(u.Hosts, u.Inject, false); err != nil {', '\t\t\tif false {\n\t\t\t\tif err := b.Allows(u.Hosts, u.Inject, false); err != nil {', R_SB2, pkg="../cmd/sandboxd")
m(SB2, '\t\tif err = b.Allows(nil, "", true); !bound {', '\t\tif err = nil; !bound {', R_SB2, pkg="../cmd/sandboxd")
m(SB2, '\t\tif err = b.Allows(nil, "", true); !bound {\n\t\t\terr = errors.New("it was sealed without a binding")', '\t\tif err = b.Allows(nil, "", true); !bound {\n\t\t\terr = nil', R_SB2, pkg="../cmd/sandboxd")
m(SB2, '\t\t\topened = append(opened, v)\n\t\t\tif _, secret', '\t\t\tif _, secret', R_SB2, pkg="../cmd/sandboxd")
m("internal/sandboxd/daemon/daemon.go", 'refs[i] = append(refs[i], Use{Ref: b.Ref, Hosts: b.Hosts, Inject: b.Inject})', 'refs[i] = append(refs[i], Use{Ref: b.Ref, Inject: b.Inject})', "TestBroker", pkg="sandboxd/daemon")
m("internal/sandboxd/daemon/server.go", '\t\t\tif refs, err = d.Broker.List(); err == nil {\n\t\t\t\tbindings, err = d.Broker.Bindings()\n\t\t\t}', '\t\t\trefs, err = d.Broker.List()', "TestBrokerList", pkg="sandboxd/daemon")
m("internal/sandboxd/brokerstore/brokerstore.go", '\t\tif b, bound, err := brokerseal.Peek(blob); err == nil && bound {', '\t\tif b, _, err := brokerseal.Peek(blob); err == nil {', "TestBindings", pkg="sandboxd/brokerstore")
SS = "internal/secrets/secrets.go"
R_SS = "TestBindings"
m(SS, '\tos.Remove(s.BindingPath(name))\n', '', R_SS, pkg="secretcmd")
m(SS, '\tif len(b.Hosts) == 0 && !b.Readable {\n\t\tif err := os.Remove(p);', '\tif false {\n\t\tif err := os.Remove(p);', R_SS, pkg="secretcmd")
m(SS, '\tif err := os.WriteFile(tmp, append(raw, \'\\n\'), 0o600); err != nil {', '\tif err := os.WriteFile(tmp, append(raw, \'\\n\'), 0o644); err != nil {', R_SS, pkg="secretcmd")
SC2 = "internal/secretcmd/secretcmd.go"
m(SC2, '\tif len(b.Hosts) > 0 && b.Inject == "" {\n\t\tb.Inject = "bearer"\n\t}', '', R_SS)
m(SC2, '\tcase bf.readable && (len(bf.hosts) > 0 || bf.inject != ""):', '\tcase false:', R_SS,
  equivalent="Validate refuses the same combination, with its own message")
m(SC2, '\tcase bf.withhold && (len(bf.hosts) > 0 || bf.inject != "" || bf.readable):', '\tcase false:', R_SS)
m(SC2, '\t\tif haveBinding {\n\t\t\tc.setBinding(st, name, b)\n\t\t}', '', R_SS)
m(SC2, '\t\tif !st.Exists(name) {\n\t\t\tc.die("Secret \'%s\' is not in the store.', '\t\tif false {\n\t\t\tc.die("Secret \'%s\' is not in the store.', R_SS)
m(SC2, '\tif !deviation.Fixed(deviation.SecretBindings) {\n\t\treturn 0\n\t}', '', R_SS)
m("internal/host/app/runsecrets.go", '\t\tsealed, err := brokerseal.SealBound(k, ref, v, b)', '\t\tsealed, err := brokerseal.SealBound(k, ref, v, brokerseal.Binding{})', "TestRunPushesBoundSecrets", pkg="host/app")
RB = "internal/cli/runbind.go"
m(RB, '\t\tcase b.Readable && !readableOK:', '\t\tcase false:', "TestBindSecrets")
m(RB, '\t\t\t\tif sessionspec.Reachable(h, egress) {', '\t\t\t\tif true {', "TestBindSecrets")
m(RB, '\t\t\tspec.Env = append(spec.Env, sessionspec.EnvVar{Name: name, Value: b.Placeholder})', '', "TestBindSecrets")
m(RB, '\t\t\tif b, _ := bind(name, dep.Egress, false); b != nil {', '\t\t\tif b, _ := bind(name, spec.Egress, false); b != nil {', "TestBindSecrets")
m(RB, '\t\tcase !ok || (!b.Readable && len(b.Hosts) == 0):', '\t\tcase !ok:', "TestBindSecrets")

# ---- found by the appliance run of the ninth round (copy mode, vetting's command-scope config)
m("internal/host/app/syncone.go", 'const CopyMode = "0750"', 'const CopyMode = "0700"', "TestLiveSync", pkg="host/app")
m("internal/host/app/syncone.go", '` -m ` + CopyMode + ` "$0"; ` +', '` -m 0700 "$0"; ` +', "TestLiveSync", pkg="host/app")
# ---- the fingerprint cache kept across runs (internal/syncproto/fpcache.go)
m("internal/syncproto/fpcache.go", '\tc.use(p)\n\treturn e.fp, true', '\treturn e.fp, true', "TestFPCache")
m("internal/syncproto/fpcache.go", 'if !identKnown || len(c.used) == 0 || !c.dirty', 'if !identKnown || !c.dirty', "TestFPCache")
m("internal/syncproto/fpcache.go", ' || cf.V != cacheFileVersion || ', ' || ', "TestFPCache")
m("internal/host/app/syncone.go", '` -m ` + CopyMode + ` "$0"; }; ` +', '` -m 0700 "$0"; }; ` +', "TestLiveSync", pkg="host/app")
m("internal/vetting/verify.go", '\tn, _ := strconv.Atoi(os.Getenv("GIT_CONFIG_COUNT"))', '\tn := 0', "TestVettingGitKeepsCallerConfig")

# ---- rebuild in the VM, the session's L7 rules, the registry warning (2026-11-26)
RBL = "internal/cli/rebuild.go"
m(RBL, '\tif tier3 || agent == "all" {', '\tif tier3 {', "TestRebuild")
m(RBL, '\t\tif err := b.Pin(tag, digest); err != nil {', '\t\tif err := error(nil); err != nil {', "TestRebuild")
m(RBL, '\t\t\t\tif !rebuildVersion.MatchString(v) {', '\t\t\t\tif false {', "TestRebuild")
m(RBL, '\t\tone("docker.io/library/sandbox:claude", "Dockerfile.claude", "--build-arg", "CLAUDE_CODE_INSTALL_REV="+c.now().Format("20060102150405"))', '\t\tone("docker.io/library/sandbox:claude", "Dockerfile.claude")', "TestRebuild")
NB = "cmd/sandbox-vm/rebuild.go"
m(NB, '\t\tif f := strings.Fields(l); len(f) >= 3 && f[0] == tag {', '\t\tif f := strings.Fields(l); len(f) >= 3 {', "TestNerdctlBuilder", pkg="../cmd/sandbox-vm")
m(NB, '\tif !digestRE.MatchString(digest) {\n\t\treturn "", fmt.Errorf("no digest', '\tif digest == "x" {\n\t\treturn "", fmt.Errorf("no digest', "TestNerdctlBuilder", pkg="../cmd/sandbox-vm")
m(NB, '\tm[short] = ref', '\tm[tag] = ref', "TestNerdctlBuilder", pkg="../cmd/sandbox-vm")
m(NB, '\tif !ok || !digestRE.MatchString(digest) {', '\tif !ok {', "TestNerdctlBuilder", pkg="../cmd/sandbox-vm")
m("cmd/sandbox-vm/launch.go", '\t\t\tif errors.Is(err, os.ErrNotExist) {\n\t\t\t\tcontinue\n\t\t\t}', '', "TestAgentImage", pkg="../cmd/sandbox-vm")
RL = "internal/cli/runl7.go"
m(RL, '\t\t\tif r.Host != l7.AnyHost && !reachableL7(r.Host, spec.Egress) {', '\t\t\tif false {', "TestL7Rules")
m(RL, '\t\trules, err := l7.ParseRules(b, src.what+" rules", false)', '\t\trules, _ := l7.ParseRules(b, src.what+" rules", false)', "TestL7Rules")
m(RL, '\t\tif !looksLikeRegistry(h) || writeDenied(rules, h) {', '\t\tif !looksLikeRegistry(h) {', "TestRegistryWarnings")
m(RL, '\t\tif r.Action != l7.Deny || r.Host == l7.AnyHost || !l7.HostMatches(r.Host, host) {', '\t\tif r.Action != l7.Deny || !l7.HostMatches(r.Host, host) {', "TestRegistryWarnings")
m(RL, '\t\t\tif m == "PUT" {', '\t\t\tif m == "DELETE" {', "TestRegistryWarnings")
m(RL, '\tfor _, b := range spec.Bindings {\n\t\thosts = append(hosts, b.Hosts...)\n\t}', '', "TestRegistryWarnings")
m("internal/l7/l7.go", '\t\t\tif denyOnly && r.Action != Deny {', '\t\t\tif false && r.Action != Deny {', "TestBaseline|TestParse", pkg="l7")

# ---- infra tokens through the broker (2026-11-26)
m("internal/host/app/runsecrets.go", '\t\tif !infraTokenNamed(t, args, a.mirrorHome()) {', '\t\tif false {', "TestRunPushesInfraTokens", pkg="host/app")
m("internal/host/app/runsecrets.go", '\t\tif !infraHostNamed(h, args) {', '\t\tif false {', "TestRunPushesInfraTokens", pkg="host/app")
m("internal/host/app/runsecrets.go", '\t\tif env == t.Env && path.Clean(p) == t.Path {', '\t\tif path.Clean(p) == t.Path {', "TestRunPushesInfraTokens", pkg="host/app")
m("internal/host/app/runsecrets.go", '\t\tif !infraEnv.MatchString(t.Env) || seen["\\x01"+t.Env] {', '\t\tif seen["\\x01"+t.Env] {', "TestRunPushesInfraTokens|TestParsePrepassInfra", pkg="host/app")
m("internal/host/app/runsecrets.go", '\t\tif !hostName.MatchString(h) || len(h) > 253 || seen["\\x02"+h] {', '\t\tif seen["\\x02"+h] {', "TestRunPushesInfraTokens|TestParsePrepassInfra", pkg="host/app")
m("internal/host/app/runsecrets.go", '\t\tb = brokerseal.Binding{Hosts: hosts, Inject: "bearer"}', '\t\tb = brokerseal.Binding{}', "TestRunPushesInfraTokens", pkg="host/app")
m("internal/host/app/runsecrets.go", '\t\tcase a == "--infra-token" && i+1 < len(out):\n\t\t\tout[i+1] = token(out[i+1])', '\t\tcase a == "--infra-token" && i+1 < len(out):\n\t\t\tout[i+1] = out[i+1]', "TestRunPushesInfraTokens", pkg="host/app")
m("internal/cli/bindings.go", '\tif s.Tier == "3" {\n\t\tfor _, t := range s.InfraTokens {', '\tif true {\n\t\tfor _, t := range s.InfraTokens {', "TestRunPrepassInfra")
m("internal/cli/bindings.go", '\t\tif h := strings.ToLower(urlHost(ep)); h != "" && !slices.Contains(out, h) {', '\t\tif h := strings.ToLower(urlHost(ep)); h != "" {', "TestRunPrepassInfra")
m("internal/cli/runbind.go", '\t\t\tspec.Env = append(spec.Env, sessionspec.EnvVar{Name: env, Value: bb.Placeholder})', '', "TestBindInfraTokens")
m("internal/cli/runbind.go", '\t\t\tb, ok = c.env.CredentialBinding(InfraRef(env))', '\t\t\tb, ok = c.env.CredentialBinding(env)', "TestBindInfraTokens")

# ---- opencode through the broker (2026-11-26)
OC = "internal/host/app/opencode.go"
R_OC = "TestRunOpencode"
m(OC, '\tif !opencodeNamed(base, args, a.getenv("OPENCODE_BASE_URL")) {', '\tif false {', R_OC, pkg="host/app")
m(OC, '\t\treturn v[len(v)-1] == base', '\t\treturn true', R_OC, pkg="host/app")
m(OC, '\tif key == "" {\n\t\ta.die("OPENCODE_API_KEY must be set', '\tif false {\n\t\ta.die("OPENCODE_API_KEY must be set', R_OC, pkg="host/app")
m(OC, '\tif n == 0 {', '\tif n < 0 {', R_OC, pkg="host/app")
m(OC, '\t\t\tif m.ID != "" {', '\t\t\tif true {', R_OC, pkg="host/app")
m(OC, 'brokerseal.Binding{Hosts: []string{strings.ToLower(u.Hostname())}, Inject: "bearer"}', 'brokerseal.Binding{}', R_OC, pkg="host/app")
m("internal/host/app/runsecrets.go", '\t\tif v := a.getenv(k); v != "" && len(v) <= 2048 && !strings.ContainsAny(v, "\\x00\\n\\r") {', '\t\tif v := a.getenv(k); false && v != "" {', R_OC, pkg="host/app")
m("internal/host/app/app.go", '\t\t\textra = append(extra, OpencodeConfigEnv+"="+prep.opencodeConfig)', '', R_OC, pkg="host/app")
OB = "internal/cli/runbind.go"
m(OB, '\tif !ok || b.Allows([]string{host}, "bearer", false) != nil || !sessionspec.Reachable(host, spec.Egress) {', '\tif !ok {', "TestBindOpencode")
m(OB, '\tif cfg == "" {\n\t\tc.die("opencode\'s configuration', '\tif false {\n\t\tc.die("opencode\'s configuration', "TestBindOpencode")
m("internal/cli/bindings.go", '\tif s.Agent == "opencode" {\n\t\tp.OpencodeBaseURL = s.BaseURL\n\t}', '', "TestBindOpencode")
m("internal/cli/bindings.go", '\t\treturn c.env.CredentialPresent(OpencodeRef)', '\t\treturn true', "TestBindOpencode|TestLaunch")

# ---- MCP dependencies on sandboxd (2026-11-26)
m("internal/cli/runlaunch.go", '\t\tcmd = append(cmd, agents.MCPLaunchArgs(s.Agent)...)', '', "TestLaunchMCP")
m("internal/cli/runlaunch.go", '\t\tif d.Kind != "mcp" {', '\t\tif d.Kind == "x" {', "TestLaunchMCP|TestLaunch")
m("internal/cli/runlaunch.go", '\t\turl := "http://" + d.Name + ".deps.sandbox.internal:" + d.Port', '\t\turl := "http://" + d.Name + ":" + d.Port', "TestLaunchMCP")
m("internal/cli/runlaunch.go", 'Target: agents.MCPConfigDir, ReadOnly: true})', 'Target: agents.MCPConfigDir})', "TestLaunchMCP")
m("internal/cli/runspec.go", '\tfor _, a := range catalogue.List(d.Path, "args") {\n\t\targs = append(args, a)\n\t}', '', "TestLaunchMCP")
m("cmd/sandbox-vm/launch.go", '\tif !sessionID.MatchString(id) {\n\t\treturn "", fmt.Errorf', '\tif false {\n\t\treturn "", fmt.Errorf', "TestWriteMCPConfig", pkg="../cmd/sandbox-vm")
m("cmd/sandbox-vm/launch.go", '\tif st, err := os.Lstat(dir); err != nil || !st.IsDir() {', '\tif false {', "TestWriteMCPConfig", pkg="../cmd/sandbox-vm")
m("internal/sandboxd/daemon/daemon.go", '\t\t\targs, imageArgs = append(append([]string(nil), args...), dep.Args...), nil // command, then args', '\t\t\timageArgs = nil', "TestDependencyArgs", pkg="sandboxd/daemon")
m("internal/sandboxd/daemon/daemon.go", '\t\tm := runtime.MicroVM{ID: cid, Runtime: spec.Runtime, Image: dep.Image, Args: args, ImageArgs: imageArgs, Env:', '\t\tm := runtime.MicroVM{ID: cid, Runtime: spec.Runtime, Image: dep.Image, Args: args, Env:', "TestDependencyArgs", pkg="sandboxd/daemon")

# ---- the sync during resume (2026-11-26)
m("internal/host/app/runsecrets.go", '\t\t\tif _, err = os.Stat(filepath.Join(a.env.StateDir, "sync", rid, "state.json")); err == nil {', '\t\t\tif true {', "TestPrepareResume", pkg="host/app")
m("internal/host/app/runsecrets.go", '\t\t\tif sessionIDRE.MatchString(a) {\n\t\t\t\treturn a\n\t\t\t}', '\t\t\treturn a', "TestPrepareResume", pkg="host/app")
m("internal/host/app/runsecrets.go", '\t\treturn nil, err\n\t}\n\tif _, err := dec.Token(); err != io.EOF {\n\t\treturn nil, errors.New("trailing data")', '\t\treturn nil, err\n\t}\n\tif false {\n\t\treturn nil, errors.New("trailing data")', "TestPrepareResume", pkg="host/app")
m("internal/host/app/app.go", '\t\t\tlive := a.startLiveSync(ep, a.prepareResume(ep, id))', '\t\t\tlive := a.startLiveSync(ep, nil)', "TestPrepareResume|TestResume", pkg="host/app",
  equivalent="no host test drives a proxied resume; the appliance run covers it")
m("internal/cli/resume.go", '\tif !resumeSessionIDRE.MatchString(id) {\n\t\treturn nil, false\n\t}', '', "TestSessionRepos")

# ---- Claude Code through the broker: onboard, the adapter, re-staged config, history (2026-11-26)
m("internal/gateway/broker/broker.go", '\t\t\tif carriesCredential(b, r) {', '\t\t\tif true {', "TestDecide|TestRateLimit", pkg="gateway/broker")
m("internal/gateway/broker/broker.go", 'var credentialHeaders = []string{"authorization", "proxy-authorization", "x-api-key", "api-key", "cookie"}', 'var credentialHeaders = []string{"authorization", "proxy-authorization"}', "TestDecide", pkg="gateway/broker")
RA = "internal/cli/runagent.go"
m(RA, '\tif c.env.CredentialPresent == nil || !c.env.CredentialPresent(ref) {', '\tif c.env.CredentialPresent == nil {', "TestSetUpAgent")
m(RA, '\t\tbound = have && sealed.Allows(ad.hosts, ad.inject, false) == nil', '\t\tbound = have', "TestSetUpAgent")
m(RA, '\t\tif s.Agent == "opencode" {\n\t\t\treturn nil\n\t\t}', '', "TestSetUpAgent")
m(RA, '\t\tif _, have := f.Config[name]; !have {', '\t\tif true {', "TestSetUpAgent|TestLaunch",
  equivalent="no staged file is also generated (.claude.json is not staged), so the operator's copy never meets it")
m(RA, '\tsort.Strings(ids)\n', '', "TestSetUpAgent")
m(RA, '\tif spec.Tier >= 2 {', '\tif spec.Tier >= 1 {', "TestLaunch|TestSetUpAgent")
m(RA, '\tspec.Env = append(spec.Env, ad.env...)\n', '', "TestLaunch|TestSetUpAgent",
  equivalent="the updater switches are not observable without the harness; the appliance run sets them")
WA = "cmd/sandbox-vm/launch.go"
m(WA, '\t\tif err := freshDir(dir, uid); err != nil {', '\t\tif err := os.MkdirAll(dir, 0o700); err != nil {', "TestWriteAgentFiles", pkg="../cmd/sandbox-vm")
m(WA, '\t\t\tif name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\\x00") {', '\t\t\tif name == "" {', "TestWriteAgentFiles", pkg="../cmd/sandbox-vm")
m(WA, '\tif !agentName.MatchString(agent) || !historyKeyRE.MatchString(key) || tier < 2 || tier > 3 {', '\tif tier > 3 {', "TestWriteAgentFiles", pkg="../cmd/sandbox-vm")
m(WA, '\t\tif st, err := os.Lstat(p); err != nil || !st.IsDir() {\n\t\t\treturn "", fmt.Errorf', '\t\tif _, err := os.Stat(p); err != nil {\n\t\t\treturn "", fmt.Errorf', "TestWriteAgentFiles", pkg="../cmd/sandbox-vm")
OB2 = "internal/host/app/onboard.go"
m(OB2, '\tif !claudeToken.Match(tok) {', '\tif len(tok) == 0 {', "TestOnboardClaude", pkg="host/app")
m(OB2, '\ta.pushAgentToken(ep, "agent.claude", tok, brokerseal.Binding{Hosts: []string{"api.anthropic.com"}, Inject: "bearer"})', '\ta.pushAgentToken(ep, "agent.claude", tok, brokerseal.Binding{})', "TestOnboardClaude", pkg="host/app")
m(OB2, 'var claudeStaged = []string{"settings.json", "CLAUDE.md"}', 'var claudeStaged = []string{"settings.json", "CLAUDE.md", ".credentials.json"}', "TestOnboardClaude", pkg="host/app")
m("internal/sessionspec/sessionspec.go", '\t\t\tif !own && (s.Tier < 2 || m.Source != HistoryPath(s.Agent, s.Tier, path.Base(m.Source)) || !historyKeyRE.MatchString(path.Base(m.Source))) {', '\t\t\tif !own && !historyKeyRE.MatchString(path.Base(m.Source)) {', "TestHistoryMounts", pkg="sessionspec")
m("internal/sandboxd/daemon/daemon.go", '\t\t\tos.RemoveAll(filepath.Join(d.SessionRoot, id, AgentConfigDir))\n', '', "TestSessionFilesRemoved", pkg="sandboxd/daemon")

# ---- flows and status on the host (2026-11-26)
m("internal/host/app/flows.go", '\tif !flowSessionRE.MatchString(id) {', '\tif false {', "TestFlows", pkg="host/app")
m("internal/host/app/flows.go", '\tif m := str("method"); m != "" {', '\tif m := str("method"); true {', "TestFlows", pkg="host/app")
m("internal/host/app/flows.go", '\tif p := str("port"); p != "" && p != "443" && !strings.Contains(dest, ":") {', '\tif p := str("port"); p != "" && !strings.Contains(dest, ":") {', "TestFlows", pkg="host/app")

# ---- Codex with a ChatGPT login: prefixed placeholders, the broker's refresh, the guest auth.json (2026-11-26)
m("internal/gateway/broker/broker.go", 'strings.TrimSpace(rest) != b.Prefix+b.Placeholder {', 'strings.TrimSpace(rest) != b.Placeholder {', "TestPrefixedPlaceholder", pkg="gateway/broker")
m("internal/gateway/broker/broker.go", '\t\tif !prefixRE.MatchString(b.Prefix) || len(b.Prefix) > 2048 || (b.Prefix != "" && b.Inject != "bearer") {', '\t\tif !prefixRE.MatchString(b.Prefix) {', "TestPrefixedPlaceholder", pkg="gateway/broker")
m("internal/sessionspec/sessionspec.go", '\t\t\tvars[b.EnvVar] = b.Prefix + b.Placeholder', '\t\t\tvars[b.EnvVar] = b.Placeholder', "TestSetUpAgentCodex", pkg="cli",
  equivalent="no binding has both a prefix and a variable today (codex's token is in a file)")
RF = "cmd/sandboxd/refresh.go"
R_RF = "TestRefreshLogin"
m(RF, '\tif time.Unix(exp, 0).Sub(now) > minValid {', '\tif time.Unix(exp, 0).Sub(now) > 0 {', R_RF, pkg="../cmd/sandboxd")
m(RF, '\tif r.RefreshToken != "" {', '\tif false {', R_RF, pkg="../cmd/sandboxd")
m(RF, '\tsealed, err := brokerseal.SealBound(key, ref, newAccess, binding)', '\tsealed, err := brokerseal.SealBound(key, ref, newAccess, brokerseal.Binding{})', R_RF, pkg="../cmd/sandboxd")
m(RF, '\tif status != http.StatusOK {', '\tif status >= 500 {', R_RF, pkg="../cmd/sandboxd")
m(RF, '\tnewExp, err := jwtExp(newAccess)\n\tif err != nil {\n\t\treturn 0, err\n\t}', '\tnewExp, _ := jwtExp(newAccess)', R_RF, pkg="../cmd/sandboxd")
m(RF, '"refresh_token": string(refresh), "scope": client.scope})', '"refresh_token": string(refresh)})', R_RF, pkg="../cmd/sandboxd")
m("cmd/sandboxd/microvm_proc.go", '\t\t\tif string(args[i]) == "-id" && string(args[i+1]) == id {', '\t\t\tif string(args[i+1]) == id {', "TestMicroVMProcess", pkg="../cmd/sandboxd")
m("cmd/sandboxd/microvm_proc.go", '\t\t\tif bytes.HasPrefix(a, []byte("/run/vc/vm/"+id+"/")) {', '\t\t\tif bytes.Contains(a, []byte(id)) {', "TestMicroVMProcess", pkg="../cmd/sandboxd")
m("internal/sandboxd/daemon/daemon.go", '\t\t\td.logf("could not remove orphan microVM %s: %v", c, err)', '\t\t\treturn err', "TestReconcileStuckOrphan", pkg="sandboxd/daemon")
m("internal/sandboxd/daemon/server.go", '\t\texp, err := d.Broker.Refresh(ctx, req.ID, d.Expiry.MaxKeepAlive()+time.Hour)', '\t\texp, err := d.Broker.Refresh(ctx, req.ID, time.Hour)', "TestBrokerRefresh", pkg="sandboxd/daemon")
RC = "internal/cli/runagent.go"
m(RC, '\t\t\tif exp, err = c.env.Launch.RefreshCredential(ref); err != nil {', '\t\t\tif _, err = c.env.Launch.RefreshCredential(ref); err != nil {', "TestSetUpAgentCodex")
m(RC, '\t\tspec.Bindings = append(spec.Bindings, sessionspec.Binding{Ref: ref, Hosts: ad.hosts, Inject: ad.inject, Placeholder: ph, Prefix: prefix})', '\t\tspec.Bindings = append(spec.Bindings, sessionspec.Binding{Ref: ref, Hosts: ad.hosts, Inject: ad.inject, Placeholder: ph})', "TestSetUpAgentCodex")
m(RC, '\t\tif !regexp.MustCompile(`(?m)^\\s*` + regexp.QuoteMeta(key) + `\\s*=`).Match(op) {', '\t\tif true {', "TestSetUpAgentCodex")
m(RC, '\tif err != nil || id.AccountID == "" {', '\tif false {', "TestSetUpAgentCodex")
OC2 = "internal/host/app/onboard_codex.go"
m(OC2, 'a.pushAgentToken(ep, "agent.codex.refresh", refresh, brokerseal.Binding{})', 'a.pushAgentToken(ep, "agent.codex.refresh", refresh, brokerseal.Binding{Hosts: []string{"auth.openai.com"}, Inject: "bearer"})', "TestOnboardCodex", pkg="host/app")
m(OC2, '\tif err := json.Unmarshal(raw, &auth); err != nil || auth.Tokens == nil || auth.Tokens.AccessToken == "" || auth.Tokens.RefreshToken == "" {', '\tif err := json.Unmarshal(raw, &auth); err != nil || auth.Tokens == nil {', "TestOnboardCodex", pkg="host/app")
m(OC2, '\t\tid.AccountID = c.Auth.AccountID', '', "TestOnboardCodex", pkg="host/app",
  equivalent="the test's login gives the account id in tokens.account_id as well as in the claims")

# ---- the v2 to v3 migration (2026-11-26)
MG = "internal/host/app/migrate.go"
R_MG = "TestMigrate|TestRemoveV2|TestInstallFindsV2"
m(MG, '\t\tif tier < 2 || tier > 3 {', '\t\tif tier > 3 {', R_MG, pkg="host/app")
m(MG, '\t\tif json.Unmarshal(b, &s) != nil || s.Agent != "claude" || !uuidRE.MatchString(s.AgentSessionID) {', '\t\tif json.Unmarshal(b, &s) != nil || !uuidRE.MatchString(s.AgentSessionID) {', R_MG, pkg="host/app")
m(MG, '\t\tif st, err := os.Stat(r); err != nil || !st.IsDir() {\n\t\t\treturn "", false\n\t\t}', '', R_MG, pkg="host/app")
m(MG, '\tsort.Strings(ids)\n\th := sha256', '\th := sha256', R_MG, pkg="host/app")
m(MG, '\t\tcase fi.Mode().IsRegular():', '\t\tcase !fi.IsDir():', R_MG, pkg="host/app")
m(MG, '\t\t\tif b, err := st.Binding(e.Name()); err != nil || len(b.Hosts) > 0 || b.Readable {', '\t\t\tif b, err := st.Binding(e.Name()); err != nil || b.Readable {', R_MG, pkg="host/app")
m(MG, '\t\t\tif !a.env.StdinTTY {\n\t\t\t\ta.die(', '\t\t\tif false {\n\t\t\t\ta.die(', R_MG, pkg="host/app")
m(MG, '\t\t\tif r := strings.TrimSpace(reply); r != "y" && r != "Y" && r != "yes" {', '\t\t\tif r := strings.TrimSpace(reply); r == "x" {', R_MG, pkg="host/app")
m(MG, '\t\t\t\tos.Remove(filepath.Join(v.agentHome, agent, f))', '', R_MG, pkg="host/app")
m(MG, '\t\tif _, err := d.Limactl(a.ctx, "delete", "--force", V2LimaInstance); err != nil {\n\t\t\ta.die(', '\t\tif _, err := d.Limactl(a.ctx, "delete", "--force", V2LimaInstance); false && err != nil {\n\t\t\ta.die(', R_MG, pkg="host/app")
m(MG, '\t\t\t\tv.limaVM = v.limaVM || n == V2LimaInstance', '\t\t\t\tv.limaVM = true', R_MG, pkg="host/app")
m("internal/host/app/install.go", '\tif !skipV2 {', '\tif true {', R_MG, pkg="host/app")
IH = "cmd/sandbox-vm/importhistory.go"
m(IH, '\t\tif name == "." || strings.HasPrefix(name, "/") || name == ".." || strings.HasPrefix(name, "../") || strings.ContainsRune(name, 0) {', '\t\tif name == "." {', "TestImportHistory", pkg="../cmd/sandbox-vm",
  equivalent="the os.Root refuses a path that leaves it; the check is defense in depth with a clearer error")
m(IH, '\t\t\tif errors.Is(err, fs.ErrExist) {\n\t\t\t\tcontinue', '\t\t\tif false {\n\t\t\t\tcontinue', "TestImportHistory", pkg="../cmd/sandbox-vm")
m(IH, '\troot, err := os.OpenRoot(dir)', '\troot, err := os.OpenRoot("/")', "TestImportHistory", pkg="../cmd/sandbox-vm")
m(IH, '\t\tif st, err := root.Lstat(p); err != nil || !st.IsDir() {', '\t\tif false {', "TestImportHistory", pkg="../cmd/sandbox-vm",
  equivalent="the Root refuses to open a file through a link anyway; the check names the path in the error")

# ---- gaps the documentation found: extra CAs per session, the settings forwarded, a local overlay (2026-11-26)
m("internal/sandboxd/daemon/tls.go", '\t\t\t\tif _, err := x509.ParseCertificate(blk.Bytes); err != nil {', '\t\t\t\tif false {', "TestExtraCAs", pkg="sandboxd/daemon")
m("internal/sandboxd/daemon/tls.go", '\t\t\t\tif blk.Type != "CERTIFICATE" {', '\t\t\t\tif false {', "TestExtraCAs", pkg="sandboxd/daemon")
m("internal/sandboxd/daemon/tls.go", '!(strings.HasSuffix(n, ".crt") || strings.HasSuffix(n, ".pem")) {', 'false {', "TestExtraCAs", pkg="sandboxd/daemon")
m("internal/sandboxd/daemon/tls.go", '\tfiles["upstream-cas.pem"] = d.TLS.roots()', '\tfiles["upstream-cas.pem"] = d.TLS.SystemRoots', "TestExtraCAs|TestIntercept|TestStart", pkg="sandboxd/daemon",
  equivalent="no daemon test reads the gateway's upstream-cas.pem with extra CAs configured; the guest bundle is tested")
m("internal/opstate/opstate.go", '\t\t\tif p != overlayDir && strings.HasPrefix(d.Name(), ".") {', '\t\t\tif false {', "TestOverlayAndSettings", pkg="host/app")
m("internal/host/app/runsecrets.go", '\tif rel, err := filepath.Rel(a.env.StateDir, p); err == nil && !strings.HasPrefix(rel, "..") {', '\tif false {', "TestOverlayAndSettings", pkg="host/app")
m("internal/host/app/runsecrets.go", '\tenv = append(env, a.overlayEnv()...)\n', '', "TestOverlayAndSettings", pkg="host/app")
m("internal/host/app/runsecrets.go", '"SANDBOX_NO_LINK_CHECK", "NO_COLOR", "USER"}', '"SANDBOX_NO_LINK_CHECK", "NO_COLOR"}', "TestOverlayAndSettings", pkg="host/app")
m("internal/host/app/runsecrets.go", '\t\t\t\traw = strings.Trim(strings.TrimSpace(string(m[1])), `"\'`)', '\t\t\t\traw = string(m[1])', "TestOverlayAndSettings", pkg="host/app")

# ---- uninstall past macOS immutable files; a refused sandboxd client (2026-11-26)
m("internal/host/app/remove_darwin.go", '\t\tif err == nil {\n\t\t\tsyscall.Chflags(q, 0)\n\t\t}', '', "TestRemoveAllImmutable", pkg="host/app")
m("internal/host/app/install.go", 'removeAll(filepath.Join(a.env.StateDir, p))', 'os.RemoveAll(filepath.Join(a.env.StateDir, p))', "TestUninstall", pkg="host/app",
  equivalent="no uninstall test has a flagged file; removeAll's own test covers the flags")
m("internal/sandboxd/daemon/server.go", '\t\t\tio.Copy(io.Discard, io.LimitReader(c, MaxRequest))\n', '', "TestServer", pkg="sandboxd/daemon",
  equivalent="the race it closes (a refused client's request write failing) does not show on these machines")

# ---- the owner's first runs: many repositories, the live sync's pace, a missing base image (2026-11-26)
m("internal/host/syncengine/engine.go", '\treturn max(interval, 2*took)', '\treturn interval', "TestNextPass", pkg="host/syncengine")
m("internal/host/syncengine/engine.go", '\t\tcase <-time.After(NextPass(interval, time.Since(start))):', '\t\tcase <-time.After(interval):', "TestNextPass|TestLiveSync", pkg="host/syncengine")
m("internal/cli/rebuild.go", '\tif agent != "base" && agent != "all" && !b.Exists("docker.io/library/sandbox:base") {', '\tif agent != "base" && !b.Exists("docker.io/library/sandbox:base") {', "TestRebuild",
  equivalent="the test's all builds with the base present; all builds base first anyway")
m("internal/cli/rebuild.go", '\tif agent != "base" && agent != "all" && !b.Exists("docker.io/library/sandbox:base") {', '\tif false {', "TestRebuild")
m("cmd/sandbox-vm/rebuild.go", '\treturn err == nil && strings.TrimSpace(ls) != ""', '\treturn err == nil', "TestNerdctlBuilder", pkg="../cmd/sandbox-vm")

# ---- the pinned known_hosts file, written while other ssh processes read it (internal/host/sshx)
m("internal/host/sshx/sshx.go", 'tmp, err := os.CreateTemp(filepath.Dir(c.KnownHosts), ".known_hosts-*") // mode 0600',
  'tmp, err := os.OpenFile(c.KnownHosts, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0o600) // mode 0600', "TestPinConcurrent", pkg="host/sshx")

# the runtime choice (owner decision, 2026-11-27): gVisor beside Kata
SS = "internal/sessionspec/sessionspec.go"
m(SS, '\tif s.Runtime != "" && s.Runtime != RuntimeKata && s.Runtime != RuntimeGVisor {', '\tif false {', "TestValidateRefuses")
m(SS, '\tif s.Runtime != "" && s.Runtime != RuntimeKata && s.Runtime != RuntimeGVisor {', '\tif s.Runtime != "" && s.Runtime != RuntimeKata {', "TestRuntimes")
m("internal/sandboxd/daemon/daemon.go", '\t\tm := runtime.MicroVM{ID: cid, Runtime: spec.Runtime, Image: dep.Image, Args: args, ImageArgs:', '\t\tm := runtime.MicroVM{ID: cid, Image: dep.Image, Args: args, ImageArgs:', "TestRuntimeOfSession", pkg="sandboxd/daemon")
m("internal/sandboxd/daemon/daemon.go", '\tagent := runtime.MicroVM{ID: id, Runtime: spec.Runtime, Image: spec.Image,', '\tagent := runtime.MicroVM{ID: id, Image: spec.Image,', "TestRuntimeOfSession", pkg="sandboxd/daemon")
m("internal/sandboxd/daemon/daemon.go", '\t\trt = sessionspec.RuntimeKata\n', '', "TestRuntimeOfSession", pkg="sandboxd/daemon")
RT = "internal/cli/run.go"
m(RT, '\t\tcase deviation.Fixed(deviation.RuntimeChoice) && val("--runtime", func(v string) { s.Runtime = v }):', '\t\tcase deviation.Fixed(deviation.RuntimeChoice) && val("--runtime", func(v string) {}):', "TestLaunchRuntime")
m(RT, '\t\t\ts.Runtime, from = config.ExtractYAMLScalar(c.env.Env.UserConfig, "runtime"), "runtime: in "+c.tilde(c.env.Env.UserConfig)', '\t\t\tfrom = "runtime: in "+c.tilde(c.env.Env.UserConfig)', "TestLaunchRuntime")
m(RT, '\t\tif s.Runtime != sessionspec.RuntimeKata && s.Runtime != sessionspec.RuntimeGVisor {', '\t\tif s.Runtime == "" {', "TestLaunchRuntime")
m(RT, '\t\tif s.Runtime == "" {\n\t\t\ts.Runtime = sessionspec.RuntimeKata\n\t\t}', '', "TestLaunchRuntime")
m("internal/cli/runlaunch.go", '\trow("Runtime", rt)', '\trow("Runtime", "kata")', "TestLaunchRuntime")
m("internal/cli/runspec.go", 'Tier: tierN, Runtime: s.Runtime,', 'Tier: tierN,', "TestLaunchRuntime")
m("internal/cli/cli.go", '\tif name == "usage_run" && deviation.Fixed(deviation.RuntimeChoice) {', '\tif false {', "TestLaunchRuntime")
MP = "cmd/sandboxd/microvm_proc.go"
m(MP, '\tcase "containerd-shim-kata-v2", "containerd-shim-runsc-v1":', '\tcase "containerd-shim-kata-v2":', "TestMicroVMProcess", pkg="../cmd/sandboxd")
m(MP, '\t\t\tif bytes.HasPrefix(a, []byte("/")) && bytes.HasSuffix(a, bundle) {', '\t\t\tif bytes.Contains(a, bundle) {', "TestMicroVMProcess", pkg="../cmd/sandboxd")
m(MP, '\t\t\ta = bytes.TrimPrefix(a, []byte("--bundle="))\n', '', "TestMicroVMProcess", pkg="../cmd/sandboxd")
m(MP, '\tcase "runsc-sandbox", "runsc-gofer":', '\tcase "runsc-sandbox":', "TestMicroVMProcess", pkg="../cmd/sandboxd")
m("internal/sandboxd/daemon/daemon.go", 'func depContainer(id, dep string) string { return dep + "." + id }', 'func depContainer(id, dep string) string { return id + "." + dep }', "TestRuntimeOfSession", pkg="sandboxd/daemon")

# shared working trees (design 5.13, OQ-06)
ST = "internal/cli/sharedtree.go"
m(ST, '\t\tif tier == s.Tier && !diffAllow {', '\t\tif tier == s.Tier {', "TestSharedTrees")
m(ST, '\t\tif tier == s.Tier && !diffAllow {', '\t\tif !diffAllow {', "TestSharedTrees")
m(ST, '\t\tif st.ID == rec.ID || !resumeSessionIDRE.MatchString(st.ID) {', '\t\tif !resumeSessionIDRE.MatchString(st.ID) {', "TestSharedTrees",
  equivalent="the launching session's own record has its own tier and allowlist, so it is skipped either way")
m(ST, '\tslices.Sort(l)\n', '', "TestSharedTrees")
m(ST, '\t\tdeny = config.ExtractYAMLScalar(ov+"/config.yaml", "shared_tree_policy") == "deny"', '\t\tdeny = false', "TestSharedTrees")
m(ST, '\t\taudit.LogEvent(rec.LogDir, "shared-tree", msg, c.stamp())\n', '', "TestSharedTrees")
m(ST, '\tif len(s.Repos) == 0 || c.env.Launch.Sessions == nil {', '\tif c.env.Launch.Sessions == nil {', "TestSharedTrees", equivalent="with no repository no other session's repos can match")
m("internal/cli/runlaunch.go", '\tc.checkSharedTrees(s, rec)\n', '', "TestLaunchSharedTree")

# the overlay's exec-vector additions (OQ-07)
OV = "internal/host/syncgate/overlay.go"
R_OV = "TestOverlayExecVectors|TestClassifyOverlayExecVectors"
m(OV, '\tov := getenv("SANDBOX_OVERLAY")', '\tov := ""', R_OV)
m(OV, '\t\tuc := getenv("USER_SANDBOX_CONFIG")', '\t\tuc := ""', R_OV)
m(OV, '\tif strings.HasPrefix(ov, "~") {', '\tif false {', R_OV)
m(OV, '\t\tif e = strings.Trim(e, "/ \\t"); e != "" {', '\t\tif e != "" {', R_OV)
m(OV, '\tif errors.Is(err, fs.ErrNotExist) {\n\t\treturn nil, nil\n\t}\n\tif err != nil {\n\t\treturn nil, err\n\t}', '\tif err != nil {\n\t\treturn nil, nil\n\t}', R_OV)
m(OV, '\t\tif loc := scalarTrailComment.FindStringIndex(v); loc != nil {', '\t\tif loc := scalarTrailComment.FindStringIndex(v); false && loc != nil {', R_OV)
m(OV, '\t\tv = strings.NewReplacer(`"`, "", `\'`, "").Replace(v)\n', '', R_OV)
m(OV, '\t\t\t\tif k == h.key(v) {', '\t\t\t\tif k == v {', R_OV)
m(OV, '\t\tif len(parts) > len(keys) {\n\t\t\tcontinue\n\t\t}\n', '', R_OV)
m(OV, '\t\t\tif keys[i] != h.key(p) {', '\t\t\tif keys[len(keys)-1-i] != h.key(p) {', R_OV)
m("internal/host/syncgate/classify.go", '\tif overlayExec(keys, h, r.ExecVectors) {', '\tif false {', R_OV)
m("internal/host/syncengine/engine.go", 'HooksPath: hooks, ExecVectors: e.ExecVectors}', 'HooksPath: hooks}', "TestOverlayExecVectorsHeld")
m("internal/host/app/syncone.go", '\t\tExecVectors: vectors,\n', '', "TestSyncOverlayExecVectors", pkg="host/app")

# log retention (OQ-08)
RTN = "internal/config/retention.go"
m(RTN, '\t\tif err != nil || n < 0 || strconv.Itoa(n) != v {', '\t\tif err != nil {', "TestRetentionMinimum", pkg="cli")
m(RTN, '\t\tout[t] = n\n', '', "TestRetentionMinimum", pkg="cli")
m("internal/audit/audit.go", '\tif s.RetentionMinDays == nil {\n\t\treturn Value{}\n\t}\n', '\tif s.RetentionMinDays == nil {\n\t\treturn Int(0)\n\t}\n', "TestRetentionMinimum", pkg="cli")
m("internal/cli/runprep.go", '\t\tif d, ok := mins[s.Tier]; ok {\n\t\t\tkeep = &d\n\t\t}\n', '', "TestRetentionMinimum")
CL = "internal/cli/sessions.go"
m(CL, '&& int64(age/(24*time.Hour)) <= int64(min) {', '&& int64(age/(24*time.Hour)) < int64(min)-30 {', "TestRetentionMinimum")
m(CL, '\t\t\treturn -1, t\n\t\t}\n\t}\n\tmax, tier := -1, "unknown"', '\t\t\treturn 99, t\n\t\t}\n\t}\n\tmax, tier := -1, "unknown"', "TestRetentionMinimum")
m(CL, '\t\tif d > max {\n\t\t\tmax, tier', '\t\tif d < max || max < 0 {\n\t\t\tmax, tier', "TestRetentionMinimum")
m(CL, '\t\t\tc.die("%v; nothing was removed.", err)', '\t\t\tc.warn("%v", err)', "TestRetentionMinimum")

# large files in parts (host to VM), held back VM to host
PT = "internal/syncagent/parts.go"
R_PT = "TestWritePart|TestLargeScanAndRead"
m(PT, '\tif h.Size <= syncproto.MaxBody || h.Size > syncproto.MaxLarge || !strings.HasPrefix(h.FP, "file:") {', '\tif h.Size <= syncproto.MaxBody || !strings.HasPrefix(h.FP, "file:") {', R_PT)
m(PT, '\tif h.Size <= syncproto.MaxBody || h.Size > syncproto.MaxLarge || !strings.HasPrefix(h.FP, "file:") {', '\tif h.Size > syncproto.MaxLarge || !strings.HasPrefix(h.FP, "file:") {', R_PT)
m(PT, '\t\tif cur != h.Base {\n\t\t\treturn syncproto.Header{Conflict: true, FP: cur}, nil\n\t\t}\n\t\tif cur == "dir" {', '\t\tif cur == "dir" {', R_PT)
m(PT, '\t} else if p.f == nil || h.Path != p.path || h.Offset != p.written || h.Size != p.size || h.FP != p.fp {', '\t} else if p.f == nil || h.Path != p.path {', R_PT)
m(PT, '\tif err != nil || got != p.fp {', '\tif err != nil {', R_PT)
m(PT, '\tdefer func() { root.Remove(p.tmp); *p = partial{} }()', '\tdefer func() { *p = partial{} }()', R_PT)
m(PT, '\tif p.exec {\n\t\tmode = 0o755\n\t}', '', "TestLargeFiles", pkg="host/syncengine")
SA = "internal/syncagent/syncagent.go"
m(SA, '\t\t\tif !large && st.Mode().IsRegular() && st.Size() > syncproto.MaxBody {', '\t\t\tif false {', R_PT)
m(SA, '\t\t\tr.TooLarge = true // larger than a message: the host\'s gate would refuse it anyway', '', R_PT)
EN = "internal/host/syncengine/engine.go"
R_EN = "TestLargeFiles|TestLargeFileOlderAgent"
m(EN, '\tscan, _, err := e.VM.Call(syncproto.Header{Op: syncproto.OpScan, Large: true}, nil)', '\tscan, _, err := e.VM.Call(syncproto.Header{Op: syncproto.OpScan}, nil)', R_EN)
m(EN, '\t\tif data == nil && strings.HasPrefix(fp, "file:") {\n\t\t\treturn e.sendParts(root, hostRel, p, h, base)\n\t\t}\n', '', R_EN)
m(EN, '\tif r.TooLarge {\n\t\treturn nil, "", errTooLarge\n\t}\n', '', R_EN)
m(EN, '\t\tif strings.HasPrefix(r.Err, "unknown operation") {', '\t\tif false {', R_EN)
m(EN, '\t\tsum.Write(buf[:n])\n', '', R_EN)
m(EN, '\tif !e.noted[n] {', '\tif true {', R_EN)
m(EN, '\tdefer func() { rep.Notes = append(rep.Notes, e.notes...) }()', '', R_EN)

# dependencies that exit are restarted (v2's pod restarts)
DP = "internal/sandboxd/daemon/deps.go"
R_DP = "TestDependencyRestarts"
m(DP, '\t\t\tif now.Sub(dep.down) < dep.delay {', '\t\t\tif false {', R_DP, pkg="sandboxd/daemon")
m(DP, '\t\t\tif dep.delay *= 2; dep.delay > DepRestartMax {', '\t\t\tif dep.delay > DepRestartMax {', R_DP, pkg="sandboxd/daemon")
m(DP, '\t\t\t\tdep.delay = DepRestartMax\n', '', R_DP, pkg="sandboxd/daemon")
m(DP, '\t\t\t\tif now.Sub(dep.started) >= DepRestartReset {', '\t\t\t\tif false {', R_DP, pkg="sandboxd/daemon")
m(DP, '\t\tif _, ok := d.live[session]; !ok {\n\t\t\tcontinue\n\t\t}\n', '', R_DP, pkg="sandboxd/daemon", equivalent="end() deletes the session's dependencies with it")
m(DP, '\t\t\t\td.audit(session, auditlog.Events, "dependency_exited", map[string]any{"name": dep.name, "restarts": dep.restarts})\n', '', R_DP, pkg="sandboxd/daemon")
m("internal/sandboxd/daemon/daemon.go", '\t\td.trackDependency(id, dep.Name, cid)\n', '', R_DP, pkg="sandboxd/daemon")
m("internal/sandboxd/daemon/daemon.go", '\tdelete(d.deps, id)\n', '', R_DP, pkg="sandboxd/daemon")
m("internal/sandboxd/daemon/daemon.go", '\td.restartDependencies(ctx, now)\n', '', R_DP, pkg="sandboxd/daemon")
m("internal/cli/runagent.go", '\tif len(projects) == 0 {\n\t\tprojects["/workspace"] = trust\n\t}\n', '', "TestClaudeJSONTrust")

# resume recreates a stopped session on sandboxd
RS = "internal/cli/resume.go"
R_RS2 = "TestResumeRecreates"
m(RS, '\t\tif onSandboxd {\n\t\t\tb = c.recreateBlocker(sj)\n\t\t}\n', '', R_RS2)
m(RS, '\t\tif len(config.ExtractYAMLList(p, "secrets")) > 0 {', '\t\tif false {', R_RS2)
m(RS, '\t\tDomains: c.resumeExtras(rec, agent, tierV), KeepAlive: keepAlive, Runtime: jqRawField(rec, "runtime", "")}', '\t\tDomains: c.resumeExtras(rec, agent, tierV), KeepAlive: keepAlive}', R_RS2)
m(RS, '\taudit.LogEvent(logDir, "recreated", "Recreated from its record by \'sandbox resume\'", c.stamp())\n', '', R_RS2)
m("internal/audit/audit.go", '\tif s.Runtime != "" {\n\t\tv, _ = v.Set("runtime", Str(s.Runtime))\n\t}\n', '', R_RS2, pkg="cli")
JN = "internal/sandboxd/journal/journal.go"
m(JN, '\t\tif err != nil || !prev.State.Ended() || len(prev.Live()) > 0 {', '\t\tif err != nil || !prev.State.Ended() {', "TestCreateAgain", pkg="sandboxd/journal")
m(JN, '\t\tif err != nil || !prev.State.Ended() || len(prev.Live()) > 0 {', '\t\tif err != nil || len(prev.Live()) > 0 {', "TestCreateAgain", pkg="sandboxd/journal")
m(JN, '\t\tif err := os.Rename(st.path(spec.ID), st.path(spec.ID)+".ended"); err != nil {', '\t\tif err := os.Remove(st.path(spec.ID)); err != nil {', "TestCreateAgain", pkg="sandboxd/journal")
m("internal/host/syncengine/git.go", '\tif err != nil || !st.Mode().IsRegular() || st.Size() <= syncproto.MaxBody {', '\tif true {', "TestLargeObject")

# the capability probe's canary (design 5.2.3 check 3)
CN = "internal/sandboxd/daemon/canary.go"
R_CN = "TestCanary"
m(CN, '\tcase r.Probe != probe:', '\tcase false:', R_CN, pkg="sandboxd/daemon")
m(CN, '\tcase r.UID != AgentUID:', '\tcase false:', R_CN, pkg="sandboxd/daemon")
m(CN, '\tcase r.Release == "" || r.Release == d.vmKernel():', '\tcase r.Release == "":', R_CN, pkg="sandboxd/daemon")
m(CN, '\tif code != 0 {', '\tif false {', R_CN, pkg="sandboxd/daemon")
m(CN, '\tdefer d.NetNS.Delete(context.WithoutCancel(ctx), ns)\n', '', R_CN, pkg="sandboxd/daemon")
m(CN, '\tif kind != runtime.Kata && kind != runtime.GVisor {', '\tif false {', R_CN, pkg="sandboxd/daemon")
m("internal/host/app/doctor.go", '\t\treport(err == nil, "a canary sandbox under "+', '\t\treport(true, "a canary sandbox under "+', "TestDoctor", pkg="host/app")

# sandbox allow on sandboxd (gateway reload)
AL = "internal/sandboxd/daemon/allow.go"
R_AL = "TestAllow"
m(AL, '\t\tif n != "" && !slices.Contains(spec.Egress.Allow, n) {', '\t\tif n != "" {', R_AL, pkg="sandboxd/daemon")
m(AL, '\tif err := spec.Validate(sessionspec.Options{}); err != nil {', '\tif false {', R_AL, pkg="sandboxd/daemon")
m(AL, '\tpol.Generation++\n', '', R_AL, pkg="sandboxd/daemon")
m(AL, '\tpol.Links[0].Allow = spec.Egress.Allow\n', '', R_AL, pkg="sandboxd/daemon")
m(AL, '\tif err := d.Journal.SetSpec(id, &spec, "allowlist extended: "+strings.Join(added, ",")); err != nil {\n\t\treturn 0, err\n\t}\n', '', R_AL, pkg="sandboxd/daemon")
m(AL, '\tif _, ok := d.live[id]; !ok {', '\tif false {', R_AL, pkg="sandboxd/daemon",
  equivalent="a session that is not running has no journal record or no live gateway slot, so Allow fails either way")
m(AL, '\t\tn = strings.TrimSpace(n)\n', '', R_AL, pkg="sandboxd/daemon")
GP = "internal/gateway/gwpolicy/gwpolicy.go"
m(GP, '\t\tal[i].Allow, al[i].BlockDomains = nil, nil\n\t\tbl[i].Allow, bl[i].BlockDomains = nil, nil\n', '', "TestSameShape", pkg="gateway/gwpolicy")
m(GP, '\tif len(a.Links) != len(b.Links) {', '\tif false {', "TestSameShape", pkg="gateway/gwpolicy")
m(GP, '\tif !bytes.Equal(ja, jb) {', '\tif false {', "TestSameShape", pkg="gateway/gwpolicy")
m("internal/cli/allow.go", '\t\t_, err := s.Allow(req.SessionID, req.Extras)', '\t\t_, err := s.Allow(req.SessionID, nil)', "TestAllowOnSandboxd")
m("internal/cli/allow.go", '\t\treturn live\n', '\t\treturn true\n', "TestAllowOnSandboxd")

# tier 3 clusters: the broker's mtls binding, the spec's checks, the deny-list
m(BR, '\t\t\tif b.Inject == "mtls" {\n\t\t\t\t// the gateway presents', '\t\t\tif false {\n\t\t\t\t// the gateway presents', R_BR, pkg="gateway/broker")
m(BR, '\t\tif b.Inject == "mtls" {\n\t\t\t// the credential is the client certificate', '\t\tif false {\n\t\t\t// the credential is the client certificate', R_BR, pkg="gateway/broker")
m(BR, '\t\tif rest, ok := cutFold(vs[0], "bearer "); !ok || strings.TrimSpace(rest) != b.Placeholder {\n\t\t\treturn nil, "", errors.New("not a bearer placeholder")\n\t\t}\n\t\treturn nil, "", nil', '\t\treturn nil, "", nil', R_BR, pkg="gateway/broker")
m(BR, '\t\tif len(b.Hosts) != 1 || !strings.HasSuffix(b.Hosts[0], kubeDomain) {', '\t\tif false {', R_BR, pkg="gateway/broker")
m("internal/brokerseal/brokerseal.go", '\tcase b.Inject == "mtls" && (len(b.Hosts) != 1 || !strings.HasSuffix(b.Hosts[0], ".gw.sandbox.internal")):', '\tcase false:', "TestBindingRules")
SK = "internal/sessionspec/sessionspec.go"
m(SK, '\tif s.Tier != 3 {\n\t\tbad("kube: clusters are for tier 3 only")', '\tif false {\n\t\tbad("kube: clusters are for tier 3 only")', "TestKube")
m(SK, '\t\tif k.Name != KubeName(i) {', '\t\tif false {', "TestKube")
m(SK, '\t\tif !slices.Contains(s.Egress.Allow, k.Name) {', '\t\tif false {', "TestKube",
  equivalent="checkBindingReach refuses the cluster's binding when its name is not allowed")
m(SK, '\t\tif n != 1 {', '\t\tif n == 0 {', "TestKube")
m(SK, '\t\t\t\tif len(b.Hosts) != 1 || (b.Inject != "bearer" && b.Inject != "mtls") {', '\t\t\t\tif false {', "TestKube")
m(SK, '\t\tif a.IsLoopback() || a.IsUnspecified() {', '\t\tif false {', "TestKube")
m(SK, '\t} else if !validHost(strings.ToLower(h)) || strings.EqualFold(h, "localhost") {', '\t} else if !validHost(strings.ToLower(h)) {', "TestKube")
m(SK, "u.User != nil || u.RawQuery != \"\"", "u.RawQuery != \"\"", "TestKube")
m(SK, '\t\tif p := x509.NewCertPool(); !p.AppendCertsFromPEM([]byte(k.CA)) {', '\t\tif false {', "TestKube")
KA = "internal/kubeapi/kubeapi.go"
m(KA, '\t\t\t"/api/v1/namespaces/*/secrets/**",\n', '', "TestDenyRules")
m(KA, '\t\t{Host: host, Methods: []string{"GET", "PUT", "PATCH", "DELETE"}', '\t\t{Host: host, Methods: []string{"GET"}', "TestDenyRules")
m(KA, '\t\t\t"/api/v1/namespaces/*/serviceaccounts/*/token",\n', '', "TestDenyRules")
m(KA, '\t\t\t"/apis/certificates.k8s.io/*/certificatesigningrequests",\n', '', "TestDenyRules")
EK = "internal/gateway/envoyconf/kube.go"
R_EK = "TestKubeBootstrap"
m(EK, '\t\tsan = obj{"san_type": "IP_ADDRESS", "matcher": obj{"exact": k.SNI}}\n', '', R_EK, pkg="gateway/envoyconf")
m(EK, '\t\tupstream["sni"] = k.SNI // an address is not sent as SNI\n', '', R_EK, pkg="gateway/envoyconf")
m(EK, '\t\ttlsCtx["tls_certificates"] = []obj{{"certificate_chain": obj{"filename": k.ClientCert}, "private_key": obj{"filename": k.ClientKey}}}\n', '', R_EK, pkg="gateway/envoyconf")
m(EK, '\t\tna["regex_rewrite"] = obj{"pattern": obj{"regex": "^(.*)$"}, "substitution": strings.TrimRight(k.PathPrefix, "/") + `\\1`}\n', '', R_EK, pkg="gateway/envoyconf")
m(EK, '\tif (k.ClientCert == "") != (k.ClientKey == "") {', '\tif false {', R_EK, pkg="gateway/envoyconf")
m(EK, '\tif !pathPrefixRE.MatchString(k.PathPrefix) {', '\tif false {', R_EK, pkg="gateway/envoyconf")
m("internal/gateway/envoyconf/intercept.go", '\t\t\t\tif i != 0 || l.BrokerSocket == "" || strings.HasPrefix(n, "*.") {', '\t\t\t\tif i != 0 || strings.HasPrefix(n, "*.") {', R_EK, pkg="gateway/envoyconf")
m("internal/gateway/envoyconf/intercept.go", '\t\tupgrades = kubeUpgrades\n', '', R_EK, pkg="gateway/envoyconf")
m("internal/gateway/broker/extproc.go", '\t\t\t\t\traw = true\n\t\t\t\t\tresp.ModeOverride = headersOnly\n', '', "TestRawStream", pkg="gateway/broker")
m("internal/gateway/broker/broker.go", '\t\t\tout.RawStream = true // allowed above for clusters only\n', '', "TestDecide|TestRawStream", pkg="gateway/broker")

# the kube helper (client certificates for a cluster's gateway)
KH = "cmd/sandboxd/broker.go"
m(KH, '\t\tif err == nil && (len(b.Hosts) != 1 || b.Hosts[0] != c.Host) {', '\t\tif false {', "TestWriteClientCerts", pkg="../cmd/sandboxd",
  equivalent="Allows refuses another host, and an mtls binding has one host (brokerseal.Validate)")
m(KH, '\t\tif err = b.Allows([]string{c.Host}, "mtls", false); !bound {', '\t\tif err = nil; !bound {', "TestWriteClientCerts", pkg="../cmd/sandboxd")
m(KH, '\t\t\tif key != nil {\n\t\t\t\treturn nil, nil, errors.New("more than one private key")', '\t\t\tif false {\n\t\t\t\treturn nil, nil, errors.New("more than one private key")', "TestWriteClientCerts", pkg="../cmd/sandboxd")
m(KH, '\treturn os.Chmod(job.Dir, 0o500)\n}\n\n// splitCertKey', '\treturn nil\n}\n\n// splitCertKey', "TestWriteClientCerts", pkg="../cmd/sandboxd")
DK = "internal/sandboxd/daemon/kube.go"
R_DK = "TestKubeSession"
m(DK, '\t\t\tif b.Inject == "mtls" && len(b.Hosts) == 1 && b.Hosts[0] == k.Name {', '\t\t\tif b.Inject == "mtls" {', R_DK, pkg="sandboxd/daemon",
  equivalent="the spec allows one binding per cluster, and an mtls binding only for a gateway name")
m(DK, '\t\t\tfiles[name] = []byte(k.CA)\n', '', R_DK, pkg="sandboxd/daemon")
m(DK, '\t\t\tku.ClientCert, ku.ClientKey = filepath.Join(certDir, c+".crt"), filepath.Join(certDir, c+".key")\n', '', R_DK, pkg="sandboxd/daemon")
m(DK, '\t\tif d.Broker == nil || d.KubeRoot == "" {', '\t\tif d.Broker == nil {', R_DK, pkg="sandboxd/daemon")
m("internal/sandboxd/daemon/daemon.go", '\t\trules[0] = append(append([]l7.Rule(nil), rules[0]...), kubeapi.DenyRules(k.Name)...)\n', '', R_DK, pkg="sandboxd/daemon")
m("internal/sandboxd/daemon/daemon.go", '\t\tcase KindKubeCerts:\n\t\t\terr = os.RemoveAll(d.kubeCertDir(id))', '\t\tcase KindKubeCerts:\n\t\t\terr = nil', R_DK, pkg="sandboxd/daemon")
m("internal/sessionspec/sessionspec.go", '\t\tserverName = k.TLSServerName\n', '', "TestUpstream")
m("internal/sessionspec/sessionspec.go", '\tprefix = strings.TrimRight(u.EscapedPath(), "/")', '\tprefix = u.EscapedPath()', "TestUpstream")

# --infra-kubeconfig, the host's half (reading, refusing, sealing) and the run's (checking, binding)
HK = "internal/host/app/kube.go"
R_HK = "TestParseKubeconfig|TestRunKubeconfigs"
m(HK, '\t\tkargs = append(kargs, "--context="+ctxName)\n', '', R_HK)
m(HK, '\t\tname = fmt.Sprintf("%s-%d", k.Context, n)\n', '', R_HK)
m(HK, '\tcase cl.Insecure:', '\tcase false:', R_HK)
m(HK, '\tcase cl.ProxyURL != "":', '\tcase false:', R_HK)
m(HK, '\tcase len(u.AuthProvider) > 0 && string(u.AuthProvider) != "null":', '\tcase false:', R_HK)
m(HK, '\t\tif err != nil || !x509.NewCertPool().AppendCertsFromPEM(ca) {', '\t\tif err != nil {', R_HK)
m(HK, '\t\tk.CA = string(ca)\n', '', R_HK)
m(HK, '\tif token == "" && u.TokenFile != "" {', '\tif false {', R_HK)
m(HK, '\t\tif b, _ := pem.Decode(kd); b == nil || !strings.HasSuffix(b.Type, "PRIVATE KEY") {', '\t\tif b, _ := pem.Decode(kd); b == nil {', R_HK)
m(HK, '\t\tk.Auth, k.value = "mtls", append(append(c, \'\\n\'), kd...)', '\t\tk.Auth, k.value = "mtls", c', R_HK)
m(HK, '\tcase len(u.Exec) > 0 && string(u.Exec) != "null":', '\tcase false:', R_HK)
m(HK, 'brokerseal.Binding{Hosts: []string{kubeName(i)}, Inject: inject})', 'brokerseal.Binding{Hosts: []string{kubeName(0)}, Inject: inject})', R_HK)
m(HK, '\tinject := map[string]string{"token": "bearer", "mtls": "mtls"}[k.Auth]\n\t\tsealed', '\tinject := "bearer"\n\t\tsealed', R_HK)
m("internal/host/app/runsecrets.go", '\ta.pushKube(ep, clusters)\n', '', R_HK)
RK = "internal/cli/runkube.go"
R_RK = "TestLaunchKube"
m(RK, '\t\t\tif a.IsLoopback() || a.IsUnspecified() {', '\t\t\tif a.IsUnspecified() {', R_RK)
m(RK, '\t\tw, err := chk.CheckEgressTargetNotBlocked(host)', '\t\tw, err := []string(nil), error(nil)', R_RK)
m(RK, '\t\tif !ok || b.Inject != inject || len(b.Hosts) != 1 || b.Hosts[0] != name {', '\t\tif !ok || b.Inject != inject {', R_RK)
m(RK, '\t\tspec.Egress.Allow = append(spec.Egress.Allow, name)\n', '', R_RK)
m(RK, '\t\tusers = append(users, map[string]any{"name": un, "user": map[string]string{"token": ph}})', '\t\tusers = append(users, map[string]any{"name": un, "user": map[string]string{"token": placeholder()}})', R_RK)
m(RK, '\t\tcontexts = append(contexts, map[string]any{"name": k.Context, "context": context{Cluster: cn, User: un, Namespace: k.Namespace}})', '\t\tcontexts = append(contexts, map[string]any{"name": k.Context, "context": context{Cluster: cn, User: un}})', R_RK)
m(RK, '\tdec.DisallowUnknownFields()\n', '', R_RK)
m(RK, '\t\tif err := sessionspec.CheckKubeServer(k.Server); err != nil {', '\t\tif err := error(nil); err != nil {', R_RK)
m("internal/cli/run.go", '\t\t} else if err == nil && len(ks) != len(s.InfraKubeconfigs) {', '\t\t} else if false {', R_RK)
m("internal/cli/runlaunch.go", '\t\tspec.Env = append(spec.Env, sessionspec.EnvVar{Name: "KUBECONFIG", Value: KubeconfigPath})\n', '', R_RK)
m("internal/cli/runlaunch.go", 'Target: KubeconfigDir, ReadOnly: true})', 'Target: KubeconfigDir})', R_RK)

# declared host endpoints (5.2.6): netd's file, the host's declaration and release, the run's use
ND = "internal/host/netd/policy.go"
m(ND, '\t\tif en.Expires.IsZero() || now().Before(en.Expires) {', '\t\tif true {', "TestDeclare|TestEndpointsFile", pkg="host/netd")
m(ND, '\t\t\tcase k == "session" && en.Session == "" && sessionRE.MatchString(v):', '\t\t\tcase k == "session":', "TestDeclare", pkg="host/netd")
m(ND, '\t\t\tcase k == "expires" && en.Expires.IsZero():', '\t\t\tcase k == "expires":', "TestDeclare", pkg="host/netd")
m(ND, '\t\t\tb.WriteString(" session=" + e.Session)\n', '', "TestDeclare", pkg="host/netd")
NDD = "internal/host/netd/declare.go"
m(NDD, '\t\t\tif e.Session != session && (e.Expires.IsZero() || now.Before(e.Expires)) {', '\t\t\tif e.Expires.IsZero() || now.Before(e.Expires) {', "TestDeclare", pkg="host/netd")
m(NDD, '\t\t\tif (e.Expires.IsZero() || now.Before(e.Expires)) && (e.Session == "" || live(e.Session)) {', '\t\t\tif e.Session == "" || live(e.Session) {', "TestDeclare", pkg="host/netd")
m(NDD, '\t\t\tif (e.Expires.IsZero() || now.Before(e.Expires)) && (e.Session == "" || live(e.Session)) {', '\t\t\tif (e.Expires.IsZero() || now.Before(e.Expires)) && live(e.Session) {', "TestDeclare", pkg="host/netd")
m(NDD, '\tif !sessionRE.MatchString(session) {', '\tif false {', "TestDeclare", pkg="host/netd")
m(NDD, '\t\tif !ep.Addr().Is4() || ep.Port() == 0 {', '\t\tif false {', "TestDeclare", pkg="host/netd")
m(NDD, '\tif len(out) == 0 {\n\t\tif err := os.Remove(path)', '\tif false {\n\t\tif err := os.Remove(path)', "TestDeclare", pkg="host/netd")
HR = "internal/host/app/hostreach.go"
R_HR = "TestRunDeclaresHostEndpoints"
m(HR, '\t\t\tif !ad.Is4() || ad.IsLoopback() || !own[ad] {', '\t\t\tif !ad.Is4() || !own[ad] {', R_HR)
m(HR, '\t\t\tif !ad.Is4() || ad.IsLoopback() || !own[ad] {', '\t\t\tif !ad.Is4() || ad.IsLoopback() {', R_HR)
m(HR, '\t\t\taddrs, _ = a.lookupHost(u.Hostname())\n', '', R_HR)
m(HR, '\t\tport = 80\n', '', R_HR)
m(HR, '\tif err := dd.DeclareEndpoints(a.ctx, id, eps, now.Add(endpointLifetime)); err != nil {', '\tif err := dd.DeclareEndpoints(a.ctx, id, eps, time.Time{}); err != nil {', R_HR)
m(HR, '\t\tif len(f) >= 3 && f[2] != "TERMINATED" && f[2] != "FAILED" {', '\t\tif len(f) >= 3 {', R_HR)
m(HR, '\t\tif len(f) >= 3 && f[2] != "TERMINATED" && f[2] != "FAILED" {', '\t\tif false {', R_HR)
m(HR, '\treturn []string{SessionIDEnv + "=" + id, HostEndpointsEnv + "=" + strings.Join(s, ",")}', '\treturn []string{HostEndpointsEnv + "=" + strings.Join(s, ",")}', R_HR)
m("internal/host/app/app.go", '\ta.releaseEndpoints(ep) // a session that ended', '\t// a session that ended', R_HR)
m("internal/host/app/app.go", '\t\ta.releaseAllEndpoints()\n', '', R_HR)
m("internal/host/app/app.go", '\t\textra = append(extra, a.declareEndpoints(prep.endpoints)...)\n', '', R_HR)
m("internal/cli/runprep.go", '\t\tif !resumeSessionIDRE.MatchString(id) || config.Exists(c.env.LogsDir+"/"+id) {', '\t\tif !resumeSessionIDRE.MatchString(id) {', "TestLaunchHostEndpoints")
m("internal/cli/runprep.go", '\t\trec.ID = id\n', '', "TestLaunchHostEndpoints")
m("internal/cli/runkube.go", '\t\tif err != nil || !ap.Addr().Is4() || ap.Port() == 0 {', '\t\tif err != nil {', "TestLaunchHostEndpoints")
m("internal/cli/runlaunch.go", '\tfor _, l := range c.hostEndpoints(spec) {', '\tfor _, l := range []string{} {', "TestLaunchHostEndpoints")

# found end to end (dev.28): the gateways' reach to their client certificates, and the key kept
# out of the gateway's broker
m(DK, '\t\t\tif err := kubeTraversable(d.KubeRoot); err != nil {', '\t\t\tif err := error(nil); err != nil {', R_DK, pkg="sandboxd/daemon")
m(DK, '\t\t\tif err := os.Chmod(d.KubeRoot, 0o711); err != nil {', '\t\t\tif err := os.Chmod(d.KubeRoot, 0o700); err != nil {', R_DK, pkg="sandboxd/daemon")
m(DK, '\t\tif st.Mode().Perm()&0o001 == 0 {', '\t\tif false {', "TestTraversable", pkg="sandboxd/daemon")
m(DK, '\t\tif p == filepath.Dir(p) {\n\t\t\treturn nil', '\t\tif true {\n\t\t\treturn nil', "TestTraversable", pkg="sandboxd/daemon")
m(KH, '\t\t\tif u.Inject == "mtls" {\n\t\t\t\t// the gateway', '\t\t\tif false {\n\t\t\t\t// the gateway', "TestOpenLinks", pkg="../cmd/sandboxd")
