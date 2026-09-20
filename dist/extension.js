"use strict";var q=Object.create;var P=Object.defineProperty;var J=Object.getOwnPropertyDescriptor;var Q=Object.getOwnPropertyNames;var X=Object.getPrototypeOf,ee=Object.prototype.hasOwnProperty;var te=(t,e)=>{for(var r in e)P(t,r,{get:e[r],enumerable:!0})},W=(t,e,r,o)=>{if(e&&typeof e=="object"||typeof e=="function")for(let i of Q(e))!ee.call(t,i)&&i!==r&&P(t,i,{get:()=>e[i],enumerable:!(o=J(e,i))||o.enumerable});return t};var S=(t,e,r)=>(r=t!=null?q(X(t)):{},W(e||!t||!t.__esModule?P(r,"default",{value:t,enumerable:!0}):r,t)),ie=t=>W(P({},"__esModule",{value:!0}),t);var ae={};te(ae,{activate:()=>se,deactivate:()=>re});module.exports=ie(ae);var c=S(require("vscode"));var h=S(require("vscode"));var G=[{id:"aws-access-key",name:"AWS Access Key ID",provider:"Amazon Web Services",pattern:/\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b/g,risk:"CRITICAL",baseConfidence:98,signals:["Known cloud credential prefix","Strict 20-char uppercase alphanumeric structure","High risk of resource hijacking"],remediation:"Immediately revoke in AWS IAM Console and replace with AWS IAM Roles or environment variables.",exampleFix:t=>`${t||"AWS_ACCESS_KEY_ID"} = process.env.AWS_ACCESS_KEY_ID`},{id:"aws-secret-key",name:"AWS Secret Access Key",provider:"Amazon Web Services",pattern:/(?:aws_secret_access_key|aws_secret_key|secret_access_key)\s*[:=]\s*["']([A-Za-z0-9/+=]{40})["']/gi,risk:"CRITICAL",minEntropy:4.2,baseConfidence:92,signals:["Contextual AWS keyword match","40-character Base64 entropy","Pairs with Access Key"],remediation:"Rotate credential immediately in AWS Secrets Manager or IAM.",exampleFix:t=>`${t||"AWS_SECRET_ACCESS_KEY"} = process.env.AWS_SECRET_ACCESS_KEY`},{id:"github-token",name:"GitHub Personal Access Token",provider:"GitHub",pattern:/\b(gh[pousr]_[A-Za-z0-9_]{36,255}|github_pat_[A-Za-z0-9_]{82})\b/g,risk:"CRITICAL",baseConfidence:99,signals:["Official GitHub token format prefix","Length and character set match","Direct repository read/write access"],remediation:"Revoke token at github.com/settings/tokens. Use GitHub Actions secrets or personal environment vars.",exampleFix:t=>`${t||"GITHUB_TOKEN"} = process.env.GITHUB_TOKEN`},{id:"openai-api-key",name:"OpenAI API Key",provider:"OpenAI",pattern:/\b(sk-proj-[A-Za-z0-9_-]{48,}|sk-[A-Za-z0-9]{32,48})\b/g,risk:"CRITICAL",minEntropy:4,baseConfidence:96,signals:["OpenAI secret key prefix (sk-)","High entropy cryptographic key","Direct model billing exposure"],remediation:"Revoke key at platform.openai.com/api-keys. Store in .env or cloud secret vault.",exampleFix:t=>`${t||"OPENAI_API_KEY"} = process.env.OPENAI_API_KEY`},{id:"anthropic-api-key",name:"Anthropic Claude API Key",provider:"Anthropic",pattern:/\b(sk-ant-[A-Za-z0-9_-]{40,})\b/g,risk:"CRITICAL",minEntropy:3.8,baseConfidence:97,signals:["Anthropic token signature (sk-ant-)","High entropy payload"],remediation:"Revoke key in Anthropic Console.",exampleFix:t=>`${t||"ANTHROPIC_API_KEY"} = process.env.ANTHROPIC_API_KEY`},{id:"stripe-secret-key",name:"Stripe Secret Key",provider:"Stripe",pattern:/\b((?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,34})\b/g,risk:"CRITICAL",baseConfidence:97,signals:["Stripe signature prefix (sk_live/rk_live)","High entropy token","Direct financial transaction privilege"],remediation:"Roll API key immediately in Stripe Dashboard > Developers > API keys.",exampleFix:t=>`${t||"STRIPE_SECRET_KEY"} = process.env.STRIPE_SECRET_KEY`},{id:"slack-bot-token",name:"Slack Token",provider:"Slack",pattern:/\b(xox[baprs]-[0-9A-Za-z-]{10,72})\b/g,risk:"HIGH",baseConfidence:95,signals:["Slack OAuth bot/user prefix (xox*)","Workspace communication exposure"],remediation:"Revoke token in api.slack.com/apps.",exampleFix:t=>`${t||"SLACK_TOKEN"} = process.env.SLACK_BOT_TOKEN`},{id:"slack-webhook",name:"Slack Webhook URL",provider:"Slack",pattern:/(https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9_]{8,12}\/B[A-Z0-9_]{8,12}\/[A-Za-z0-9_]{24})/g,risk:"HIGH",baseConfidence:98,signals:["Slack Incoming Webhook URL","Allows channel spam and impersonation"],remediation:"Delete webhook in Slack App configuration.",exampleFix:t=>`${t||"SLACK_WEBHOOK_URL"} = process.env.SLACK_WEBHOOK_URL`},{id:"private-key",name:"Private Encryption Key",provider:"Cryptography",pattern:/(-----BEGIN (?:RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----[\s\S]*?-----END (?:RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----)/g,risk:"CRITICAL",baseConfidence:100,signals:["Standard PEM certificate container","Private cryptographic key","Complete cryptographic compromise"],remediation:"Immediately regenerate keypair, update authorized_keys or TLS certificates, and do not commit.",exampleFix:()=>"PRIVATE_KEY = fs.readFileSync(process.env.KEY_PATH, 'utf8')"},{id:"database-url",name:"Database Connection String with Credentials",provider:"Database",pattern:/\b((?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis):\/\/[^:\s'"]+:([^@\s'"]+)@[a-zA-Z0-9.-]+(?::[0-9]+)?\/[^\s'"]+)/gi,risk:"HIGH",minEntropy:3.2,baseConfidence:90,signals:["Database URI scheme with embedded user:password","Production data exposure risk"],remediation:"Extract credentials to DATABASE_URL environment variable or use IAM authentication.",exampleFix:t=>`${t||"DATABASE_URL"} = process.env.DATABASE_URL`},{id:"jwt-token",name:"JSON Web Token (JWT)",provider:"Identity / Auth",pattern:/\b(ey[A-Za-z0-9_-]{15,}\.ey[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{10,})\b/g,risk:"HIGH",minEntropy:4.1,baseConfidence:86,signals:["Base64 header.payload.signature JWT structure","Authentication session hijacking risk"],remediation:"Store JWTs in secure cookies or memory; never hardcode tokens in client or server files.",exampleFix:t=>`${t||"AUTH_TOKEN"} = process.env.AUTH_TOKEN`},{id:"generic-api-key",name:"Generic API Key / Secret Assignment",provider:"Generic Credential",pattern:/(?:(?:api_?key|secret_?key|auth_?token|client_?secret|access_?token|private_?key)\s*[:=]\s*["']([A-Za-z0-9_.~-]{20,90})["'])/gi,risk:"MEDIUM",minEntropy:4.1,baseConfidence:80,signals:["Sensitive identifier name assignment","High entropy string literal"],remediation:"Move confidential credential to .env file.",exampleFix:t=>`${t||"API_KEY"} = process.env.${(t||"API_KEY").toUpperCase()}`}];function N(t){if(!t||t.length===0)return 0;let e={};for(let i=0;i<t.length;i++){let s=t[i];e[s]=(e[s]||0)+1}let r=0,o=t.length;for(let i in e){let s=e[i]/o;r-=s*Math.log2(s)}return Math.round(r*100)/100}function B(t){if(!t)return"[EMPTY]";let e=t.length;if(e<=8)return"***[REDACTED]***";let r=Math.min(4,Math.floor(e*.25)),o=Math.min(4,Math.floor(e*.25)),i=e-r-o;return t.substring(0,r)+"*".repeat(Math.max(4,i))+t.substring(e-o)}var ne=[/example/i,/placeholder/i,/your[_-]?api[_-]?key/i,/dummy/i,/test[_-]?token/i,/xxxx+/i,/^123456789[0-9]*$/,/AKIAIOSFODNN7EXAMPLE/i,/insert[_-]?here/i,/replace[_-]?me/i];function oe(t){return ne.some(e=>e.test(t))}function _(t,e,r,o=3.4){let i=[],s=t.split(/\r?\n/),d=/(test|spec|mock|fixture|sample)/i.test(e);for(let n of G){n.pattern.lastIndex=0;let p;for(;(p=n.pattern.exec(t))!==null;){let g=p[1]||p[0],f=p.index;if(oe(g))continue;let u=N(g),x=n.minEntropy??(n.risk==="CRITICAL"?0:o);if(x>0&&u<x)continue;let b=t.substring(0,f).split(/\r?\n/),D=b.length,Z=b[b.length-1].length+1,K=e;r&&e.startsWith(r)&&(K=e.substring(r.length).replace(/^[\\/]+/,""));let E=n.baseConfidence;d&&(E=Math.max(50,E-20)),u>4.5&&(E=Math.min(100,E+5));let H=(s[D-1]||"").match(/(?:const|let|var|val|\$)\s+([a-zA-Z0-9_]+)/i),V=H?H[1]:void 0,j=`sec_${Math.random().toString(36).substring(2,9)}`;i.push({id:j,type:n.name,provider:n.provider,file:K,fullPath:e,line:D,column:Z,length:g.length,rawSecret:g,redactedSecret:B(g),risk:n.risk,confidence:E,entropy:u,signals:[...n.signals,`Entropy: ${u} bits/char`],remediation:n.remediation,exampleFix:n.exampleFix(V||""),status:"ACTIVE",detectedAt:new Date().toISOString()})}}let l=[];for(let n of i){let p=l.findIndex(g=>g.line===n.line&&(g.rawSecret.includes(n.rawSecret)||n.rawSecret.includes(g.rawSecret)));if(p===-1)l.push(n);else{let g=l[p];(g.provider==="Generic Credential"&&n.provider!=="Generic Credential"||n.confidence>g.confidence)&&(l[p]=n)}}return l}var F=class{diagnosticCollection;currentFindings=new Map;onFindingsChangedEmitter=new h.EventEmitter;onFindingsChanged=this.onFindingsChangedEmitter.event;constructor(){this.diagnosticCollection=h.languages.createDiagnosticCollection("secret-leak-detector")}getDiagnosticCollection(){return this.diagnosticCollection}getAllFindings(){let e=[];for(let r of this.currentFindings.values())e.push(...r);return e}clear(){this.diagnosticCollection.clear(),this.currentFindings.clear(),this.onFindingsChangedEmitter.fire([])}scanDocument(e){if(e.uri.scheme!=="file")return[];let r=e.getText(),o=h.workspace.getWorkspaceFolder(e.uri),i=o?o.uri.fsPath:void 0,s=_(r,e.uri.fsPath,i);this.currentFindings.set(e.uri.fsPath,s);let d=[];for(let l of s){let n=Math.max(0,l.line-1),p=Math.max(0,l.column-1),g=p+l.length,f=new h.Range(n,p,n,g),u=h.DiagnosticSeverity.Warning;l.risk==="CRITICAL"||l.risk==="HIGH"?u=h.DiagnosticSeverity.Error:l.risk==="LOW"&&(u=h.DiagnosticSeverity.Information);let x=new h.Diagnostic(f,`[Secret Leak Detector] ${l.type} detected! Confidence: ${l.confidence}%. ${l.remediation}`,u);x.code={value:l.id,target:h.Uri.parse("https://github.com/MokuLakshithReddy/Secret_Leak_Detector")},x.source="Secret Leak Detector",d.push(x)}return this.diagnosticCollection.set(e.uri,d),this.onFindingsChangedEmitter.fire(this.getAllFindings()),s}removeDocument(e){this.diagnosticCollection.delete(e),this.currentFindings.delete(e.fsPath),this.onFindingsChangedEmitter.fire(this.getAllFindings())}dispose(){this.diagnosticCollection.dispose(),this.onFindingsChangedEmitter.dispose()}};var v=S(require("vscode")),y=S(require("fs")),O=S(require("path")),A=class{static providedCodeActionKinds=[v.CodeActionKind.QuickFix];diagnosticProvider;constructor(e){this.diagnosticProvider=e}provideCodeActions(e,r,o){let i=[],s=o.diagnostics.filter(l=>l.source==="Secret Leak Detector");if(s.length===0)return i;let d=this.diagnosticProvider.getAllFindings();for(let l of s){let n=d.find(f=>f.fullPath===e.uri.fsPath&&f.line===l.range.start.line+1);if(!n)continue;let p=this.createMoveToEnvAction(e,l.range,n);i.push(p);let g=new v.CodeAction("Ignore this finding (False Positive)",v.CodeActionKind.QuickFix);g.command={command:"secret-leak-detector.ignoreFinding",title:"Ignore Finding",arguments:[n.id]},i.push(g)}return i}createMoveToEnvAction(e,r,o){let i=new v.CodeAction(`\u{1F6E1}\uFE0F Move ${o.type} to .env and replace with environment variable`,v.CodeActionKind.QuickFix);return i.isPreferred=!0,i.command={command:"secret-leak-detector.remediateFinding",title:"Move to .env",arguments:[e.uri,r,o]},i}static async executeRemediation(e,r,o){let i=v.workspace.getWorkspaceFolder(e);if(!i){v.window.showErrorMessage("No workspace folder found to save .env file.");return}let s=i.uri.fsPath,d=O.join(s,".env"),l=O.join(s,".gitignore"),n="SECRET_KEY";o.type.includes("AWS Access Key")?n="AWS_ACCESS_KEY_ID":o.type.includes("AWS Secret")?n="AWS_SECRET_ACCESS_KEY":o.type.includes("GitHub")?n="GITHUB_TOKEN":o.type.includes("OpenAI")?n="OPENAI_API_KEY":o.type.includes("Anthropic")?n="ANTHROPIC_API_KEY":o.type.includes("Stripe")?n="STRIPE_SECRET_KEY":o.type.includes("Slack")?n="SLACK_TOKEN":o.type.includes("Database")?n="DATABASE_URL":n=`${o.provider.replace(/[^a-zA-Z0-9]/g,"_").toUpperCase()}_API_KEY`;let p=`
${n}="${o.rawSecret}"
`;try{y.appendFileSync(d,p,"utf8")}catch(u){v.window.showErrorMessage(`Failed to write to .env: ${u}`);return}y.existsSync(l)?y.readFileSync(l,"utf8").includes(".env")||y.appendFileSync(l,`
# Credentials
.env
.env.*.local
`,"utf8"):y.writeFileSync(l,`# Credentials
.env
.env.*.local
`,"utf8");let g=new v.WorkspaceEdit,f=`process.env.${n}`;g.replace(e,r,f),await v.workspace.applyEdit(g),v.window.showInformationMessage(`\u2705 Moved ${o.type} to .env (${n}) and protected in .gitignore!`)}};var a=S(require("vscode")),R=class{_onDidChangeTreeData=new a.EventEmitter;onDidChangeTreeData=this._onDidChangeTreeData.event;findings=[];updateFindings(e){this.findings=e,this._onDidChangeTreeData.fire()}getTreeItem(e){return e}getChildren(e){if(!e){if(this.findings.length===0){let i=new k("No Leaks Detected (Safe)",a.TreeItemCollapsibleState.None);return i.iconPath=new a.ThemeIcon("shield-check",new a.ThemeColor("testing.iconPassed")),i.description="Workspace is clean",Promise.resolve([i])}let r=["CRITICAL","HIGH","MEDIUM","LOW"],o=[];for(let i of r){let s=this.findings.filter(d=>d.risk===i).length;if(s>0){let d=new k(`${i} Risk (${s})`,a.TreeItemCollapsibleState.Expanded,i);i==="CRITICAL"?d.iconPath=new a.ThemeIcon("error",new a.ThemeColor("errorForeground")):i==="HIGH"?d.iconPath=new a.ThemeIcon("warning",new a.ThemeColor("editorWarning.foreground")):i==="MEDIUM"?d.iconPath=new a.ThemeIcon("info",new a.ThemeColor("editorInfo.foreground")):d.iconPath=new a.ThemeIcon("pass",new a.ThemeColor("testing.iconPassed")),o.push(d)}}return Promise.resolve(o)}if(e.contextValue){let r=e.contextValue,i=this.findings.filter(s=>s.risk===r).map(s=>{let d=new k(`${s.type}`,a.TreeItemCollapsibleState.None);return d.description=`${s.file}:${s.line}`,d.tooltip=new a.MarkdownString(`**${s.type}** (${s.provider})

- **Risk:** ${s.risk}
- **Confidence:** ${s.confidence}%
- **Entropy:** ${s.entropy} bits/char
- **Secret:** \`${s.redactedSecret}\`

*${s.remediation}*`),d.iconPath=new a.ThemeIcon("key"),d.command={command:"vscode.open",title:"Jump to Secret",arguments:[a.Uri.file(s.fullPath),{selection:new a.Range(s.line-1,s.column-1,s.line-1,s.column-1+s.length)}]},d});return Promise.resolve(i)}return Promise.resolve([])}},L=class{_onDidChangeTreeData=new a.EventEmitter;onDidChangeTreeData=this._onDidChangeTreeData.event;findingsCount=0;isGit=!0;update(e,r){this.findingsCount=e,this.isGit=r,this._onDidChangeTreeData.fire()}getTreeItem(e){return e}getChildren(){let e=[],r=new k(this.findingsCount===0?"Status: Protected":`Status: ${this.findingsCount} Leaks Active`,a.TreeItemCollapsibleState.None);r.iconPath=new a.ThemeIcon(this.findingsCount===0?"check":"alert",this.findingsCount===0?new a.ThemeColor("testing.iconPassed"):new a.ThemeColor("errorForeground")),e.push(r);let o=new k("Run Full Workspace Scan",a.TreeItemCollapsibleState.None);o.iconPath=new a.ThemeIcon("search"),o.command={command:"secret-leak-detector.scanWorkspace",title:"Scan Workspace"},e.push(o);let i=new k("Check Git Staged Changes",a.TreeItemCollapsibleState.None);i.iconPath=new a.ThemeIcon("git-commit"),i.command={command:"secret-leak-detector.scanStaged",title:"Scan Staged Changes"},e.push(i);let s=new k("Open Interactive Dashboard",a.TreeItemCollapsibleState.None);s.iconPath=new a.ThemeIcon("dashboard"),s.command={command:"secret-leak-detector.openDashboard",title:"Open Dashboard"},e.push(s);let d=new k("Install Pre-Commit Hook",a.TreeItemCollapsibleState.None);return d.iconPath=new a.ThemeIcon("terminal"),d.command={command:"secret-leak-detector.installGitHook",title:"Install Hook"},e.push(d),Promise.resolve(e)}},k=class extends a.TreeItem{constructor(e,r,o){super(e,r),this.contextValue=o}};var m=S(require("vscode")),w=class t{static currentPanel;static viewType="secretLeakDetectorDashboard";_panel;_extensionUri;_disposables=[];_findings=[];static createOrShow(e,r){let o=m.window.activeTextEditor?m.window.activeTextEditor.viewColumn:void 0;if(t.currentPanel){t.currentPanel._panel.reveal(o),t.currentPanel.updateFindings(r);return}let i=m.window.createWebviewPanel(t.viewType,"\u{1F510} Secret Leak Detector Dashboard",o||m.ViewColumn.One,{enableScripts:!0,retainContextWhenHidden:!0,localResourceRoots:[e]});t.currentPanel=new t(i,e,r)}constructor(e,r,o){this._panel=e,this._extensionUri=r,this._findings=o,this._update(),this._panel.onDidDispose(()=>this.dispose(),null,this._disposables),this._panel.webview.onDidReceiveMessage(async i=>{switch(i.command){case"scanWorkspace":m.commands.executeCommand("secret-leak-detector.scanWorkspace");return;case"scanStaged":m.commands.executeCommand("secret-leak-detector.scanStaged");return;case"installHook":m.commands.executeCommand("secret-leak-detector.installGitHook");return;case"openFile":if(i.file&&i.line){let s=await m.workspace.openTextDocument(m.Uri.file(i.file));await m.window.showTextDocument(s,{selection:new m.Range(i.line-1,0,i.line-1,0)})}return}},null,this._disposables)}updateFindings(e){this._findings=e,this._panel.webview.postMessage({command:"updateData",findings:this._findings}),this._update()}dispose(){for(t.currentPanel=void 0,this._panel.dispose();this._disposables.length;){let e=this._disposables.pop();e&&e.dispose()}}_update(){this._panel.webview.html=this._getHtmlForWebview()}_getHtmlForWebview(){return`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Secret Leak Detector</title>
  <style>
    :root {
      --bg: #0b0f17;
      --card-bg: #131926;
      --border: #1f293d;
      --text: #e2e8f0;
      --text-muted: #8492a6;
      --accent: #00e5b0;
      --critical: #ff3b3b;
      --high: #ff8c00;
      --medium: #e8b800;
      --low: #00e5b0;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
      padding: 24px;
      line-height: 1.5;
    }
    .header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding-bottom: 20px;
      border-bottom: 1px solid var(--border);
      margin-bottom: 24px;
    }
    .title-area {
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .title-area h1 {
      font-size: 22px;
      font-weight: 700;
      letter-spacing: -0.5px;
    }
    .badge-live {
      background: rgba(0, 229, 176, 0.15);
      color: var(--accent);
      border: 1px solid rgba(0, 229, 176, 0.3);
      padding: 3px 10px;
      border-radius: 9999px;
      font-size: 12px;
      font-weight: 600;
    }
    .btn-group {
      display: flex;
      gap: 10px;
    }
    button {
      background: var(--card-bg);
      color: var(--text);
      border: 1px solid var(--border);
      padding: 8px 16px;
      border-radius: 6px;
      cursor: pointer;
      font-weight: 600;
      font-size: 13px;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      transition: all 0.2s;
    }
    button:hover {
      background: #1a2336;
      border-color: #2e3d5a;
    }
    button.primary {
      background: var(--accent);
      color: #0b0f17;
      border-color: var(--accent);
    }
    button.primary:hover {
      background: #00c799;
    }
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 16px;
      margin-bottom: 28px;
    }
    .stat-card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 16px 20px;
    }
    .stat-label {
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.8px;
      color: var(--text-muted);
      margin-bottom: 6px;
    }
    .stat-value {
      font-size: 28px;
      font-weight: 700;
    }
    .stat-value.critical { color: var(--critical); }
    .stat-value.high { color: var(--high); }
    .stat-value.clean { color: var(--accent); }

    .tabs {
      display: flex;
      gap: 12px;
      margin-bottom: 16px;
      border-bottom: 1px solid var(--border);
    }
    .tab {
      padding: 10px 16px;
      font-size: 14px;
      font-weight: 600;
      cursor: pointer;
      border-bottom: 2px solid transparent;
      color: var(--text-muted);
    }
    .tab.active {
      color: var(--accent);
      border-bottom-color: var(--accent);
    }

    .card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      overflow: hidden;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      text-align: left;
      font-size: 13px;
    }
    th {
      background: #0e1420;
      padding: 12px 16px;
      color: var(--text-muted);
      font-weight: 600;
      border-bottom: 1px solid var(--border);
    }
    td {
      padding: 14px 16px;
      border-bottom: 1px solid #161e2e;
    }
    tr:hover td {
      background: rgba(255,255,255,0.02);
    }
    .tag {
      display: inline-block;
      padding: 3px 8px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 700;
    }
    .tag-CRITICAL { background: rgba(255, 59, 59, 0.15); color: var(--critical); }
    .tag-HIGH { background: rgba(255, 140, 0, 0.15); color: var(--high); }
    .tag-MEDIUM { background: rgba(232, 184, 0, 0.15); color: var(--medium); }
    .tag-LOW { background: rgba(0, 229, 176, 0.15); color: var(--low); }

    .secret-code {
      font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, Courier, monospace;
      background: #080b11;
      padding: 3px 8px;
      border-radius: 4px;
      border: 1px solid #1f293d;
      font-size: 12px;
      color: #93c5fd;
    }
    .file-link {
      color: #60a5fa;
      cursor: pointer;
      text-decoration: underline;
    }
    .empty-state {
      padding: 48px;
      text-align: center;
      color: var(--text-muted);
    }
    .empty-icon {
      font-size: 40px;
      margin-bottom: 12px;
    }
    .remediation-box {
      font-size: 12px;
      color: #cbd5e1;
      background: #0b0f17;
      padding: 8px 12px;
      border-radius: 6px;
      border-left: 3px solid var(--accent);
      margin-top: 6px;
    }
  </style>
</head>
<body>
  <div class="header">
    <div class="title-area">
      <h1>\u{1F510} Secret Leak Detector</h1>
      <span class="badge-live">LIVE MONITORING</span>
    </div>
    <div class="btn-group">
      <button onclick="scanStaged()">\u26A1 Scan Staged</button>
      <button class="primary" onclick="scanWorkspace()">\u{1F50D} Full Workspace Scan</button>
      <button onclick="installHook()">\u{1F6E1}\uFE0F Install Hook</button>
    </div>
  </div>

  <div class="stats-grid">
    <div class="stat-card">
      <div class="stat-label">Total Leaks Detected</div>
      <div class="stat-value" id="stat-total">0</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Critical Risks</div>
      <div class="stat-value critical" id="stat-critical">0</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">High Risks</div>
      <div class="stat-value high" id="stat-high">0</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Commit Guardrail</div>
      <div class="stat-value clean" id="stat-guard">ACTIVE</div>
    </div>
  </div>

  <div class="tabs">
    <div class="tab active" onclick="switchTab('findings')">Active Findings</div>
    <div class="tab" onclick="switchTab('blast')">Blast Radius & Providers</div>
    <div class="tab" onclick="switchTab('workflow')">Workflow Architecture</div>
  </div>

  <div id="tab-findings" class="card">
    <table>
      <thead>
        <tr>
          <th>Risk</th>
          <th>Type / Provider</th>
          <th>File & Line</th>
          <th>Redacted Secret</th>
          <th>Confidence</th>
          <th>Entropy</th>
          <th>Action</th>
        </tr>
      </thead>
      <tbody id="findings-table-body">
      </tbody>
    </table>
    <div id="empty-state" class="empty-state" style="display: none;">
      <div class="empty-icon">\u{1F6E1}\uFE0F</div>
      <h3>No secrets detected in current files!</h3>
      <p>Your workspace and staged commits are currently safe from credential leaks.</p>
    </div>
  </div>

  <div id="tab-blast" class="card" style="display: none; padding: 24px;">
    <h3 style="margin-bottom: 16px;">Trace & Blast Radius Analysis</h3>
    <p style="color: var(--text-muted); margin-bottom: 20px;">
      Correlates credential exposures across files and commits to prevent lateral propagation.
    </p>
    <div id="blast-content"></div>
  </div>

  <div id="tab-workflow" class="card" style="display: none; padding: 24px;">
    <h3 style="margin-bottom: 16px;">Zero-Leak Enforcement Pipeline</h3>
    <pre style="background: #080b11; padding: 18px; border-radius: 8px; font-family: monospace; color: #00e5b0; line-height: 1.6;">
DETECT (Pattern + Shannon Entropy)
   \u2193
PROVE (Verification & Provider Match)
   \u2193
TRACE (Blast Radius across Files/Git)
   \u2193
BLOCK (Intercept git commit / git push)
   \u2193
FIX (One-click Extraction to .env)
   \u2193
RESCAN (Validate Safe State)
   \u2193
ALLOW (Commit Proceeds)
    </pre>
  </div>

  <script>
    const vscode = acquireVsCodeApi();
    let findings = ${JSON.stringify(this._findings)};

    function render() {
      const tbody = document.getElementById('findings-table-body');
      const emptyState = document.getElementById('empty-state');
      
      const totalCount = findings.length;
      const criticalCount = findings.filter(f => f.risk === 'CRITICAL').length;
      const highCount = findings.filter(f => f.risk === 'HIGH').length;

      document.getElementById('stat-total').innerText = totalCount;
      document.getElementById('stat-critical').innerText = criticalCount;
      document.getElementById('stat-high').innerText = highCount;
      document.getElementById('stat-guard').innerText = totalCount > 0 ? 'BLOCKING' : 'READY';
      document.getElementById('stat-guard').className = totalCount > 0 ? 'stat-value critical' : 'stat-value clean';

      if (findings.length === 0) {
        tbody.innerHTML = '';
        emptyState.style.display = 'block';
        return;
      }

      emptyState.style.display = 'none';
      tbody.innerHTML = findings.map(f => \`
        <tr>
          <td><span class="tag tag-\${f.risk}">\${f.risk}</span></td>
          <td>
            <strong>\${f.type}</strong><br/>
            <span style="font-size: 11px; color: var(--text-muted)">\${f.provider}</span>
          </td>
          <td>
            <span class="file-link" onclick="openFile('\${f.fullPath.replace(/\\\\/g, '\\\\\\\\')}', \${f.line})">
              \${f.file}:\${f.line}
            </span>
          </td>
          <td><span class="secret-code">\${f.redactedSecret}</span></td>
          <td><strong>\${f.confidence}%</strong></td>
          <td>\${f.entropy} b/c</td>
          <td>
            <button onclick="openFile('\${f.fullPath.replace(/\\\\/g, '\\\\\\\\')}', \${f.line})">View Line</button>
          </td>
        </tr>
        <tr>
          <td colspan="7" style="padding-top: 0; padding-bottom: 14px; background: #0e1420;">
            <div class="remediation-box">
              <strong>Remediation:</strong> \${f.remediation}<br/>
              <code>\${f.exampleFix}</code>
            </div>
          </td>
        </tr>
      \`).join('');

      // Blast radius view
      const blastDiv = document.getElementById('blast-content');
      const providers = {};
      findings.forEach(f => {
        providers[f.provider] = (providers[f.provider] || 0) + 1;
      });

      blastDiv.innerHTML = \`
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px;">
          <div style="background: #080b11; padding: 16px; border-radius: 6px;">
            <h4>Affected Providers</h4>
            <ul style="margin-top: 8px; padding-left: 20px;">
              \${Object.entries(providers).map(([p, count]) => \`<li><strong>\${p}</strong>: \${count} occurrence(s)</li>\`).join('')}
            </ul>
          </div>
          <div style="background: #080b11; padding: 16px; border-radius: 6px;">
            <h4>Total Exposure Surface</h4>
            <p style="margin-top: 8px;">\${totalCount} active credentials identified across \${new Set(findings.map(f => f.file)).size} file(s).</p>
          </div>
        </div>
      \`;
    }

    function switchTab(tabId) {
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      document.getElementById('tab-findings').style.display = tabId === 'findings' ? 'block' : 'none';
      document.getElementById('tab-blast').style.display = tabId === 'blast' ? 'block' : 'none';
      document.getElementById('tab-workflow').style.display = tabId === 'workflow' ? 'block' : 'none';
      event.target.classList.add('active');
    }

    function scanWorkspace() {
      vscode.postMessage({ command: 'scanWorkspace' });
    }

    function scanStaged() {
      vscode.postMessage({ command: 'scanStaged' });
    }

    function installHook() {
      vscode.postMessage({ command: 'installHook' });
    }

    function openFile(file, line) {
      vscode.postMessage({ command: 'openFile', file, line });
    }

    window.addEventListener('message', event => {
      const message = event.data;
      if (message.command === 'updateData') {
        findings = message.findings;
        render();
      }
    });

    render();
  </script>
</body>
</html>`}};var z=require("child_process"),Y=require("util"),I=S(require("fs")),$=S(require("path"));var U=(0,Y.promisify)(z.exec),M=class{workspaceRoot;constructor(e){this.workspaceRoot=e}async isGitRepo(){try{return await U("git rev-parse --is-inside-work-tree",{cwd:this.workspaceRoot}),!0}catch{return!1}}async scanStagedChanges(){if(!await this.isGitRepo())return[];try{let{stdout:e}=await U("git diff --cached --unified=0",{cwd:this.workspaceRoot});if(!e||e.trim().length===0)return[];let r=[],o=e.split(/^diff --git /m);for(let i of o){if(!i.trim())continue;let s=i.match(/^[ab]\/(.+?) [ab]\/(.+)/m)||i.match(/^\+\+\+ b\/(.+)/m),d=s?s[1]:"staged-file",l=$.join(this.workspaceRoot,d),n=i.split(`
`).filter(p=>p.startsWith("+")&&!p.startsWith("+++")).map(p=>p.substring(1)).join(`
`);if(n.trim()){let p=_(n,l,this.workspaceRoot);r.push(...p)}}return r}catch(e){return console.error("Failed to run git diff --cached:",e),[]}}formatTerminalBlockedMessage(e){let o=e.filter(s=>s.risk==="CRITICAL")[0]||e[0];return`
============================================================
\u274C COMMIT BLOCKED BY SECRET LEAK DETECTOR
============================================================
\u{1F6A8} Security Risk: Hard-coded secret detected before commit!

Finding Details:
------------------------------------------------------------
\u2022 Type:        ${o.type}
\u2022 Provider:    ${o.provider}
\u2022 File:        ${o.file} (Line ${o.line})
\u2022 Secret:      ${o.redactedSecret}
\u2022 Risk Level:  ${o.risk}
\u2022 Confidence:  ${o.confidence}%
\u2022 Entropy:     ${o.entropy} bits/char

Signals Detected:
${o.signals.map(s=>`  - ${s}`).join(`
`)}

Recommended Remediation:
------------------------------------------------------------
${o.remediation}

Example Fix:
  ${o.exampleFix}

After fixing:
  1. Replace the secret in ${o.file} with an environment variable.
  2. Add the sensitive value to your local .env (ensure .env is in .gitignore!).
  3. Run 'git add ${o.file}'
  4. Run your 'git commit' again.
============================================================
`}async installPreCommitHook(){if(!await this.isGitRepo())return{success:!1,message:"Workspace is not a Git repository."};let e=$.join(this.workspaceRoot,".git","hooks");if(!I.existsSync(e))try{I.mkdirSync(e,{recursive:!0})}catch(i){return{success:!1,message:`Could not create .git/hooks directory: ${i}`}}let r=$.join(e,"pre-commit"),o=`#!/bin/sh
# Secret Leak Detector Pre-Commit Hook
# Automatically blocks git commit if secrets are detected in staged changes

echo "\u{1F510} [Secret Leak Detector] Scanning staged changes for credentials..."

DIFF=$(git diff --cached --unified=0)

# Check for AWS Access Keys
if echo "$DIFF" | grep -E '^[+]' | grep -E -q '(AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}'; then
    echo "\u274C COMMIT BLOCKED: Potential AWS Access Key found in staged changes!"
    echo "Please remove the credential or use an environment variable before committing."
    exit 1
fi

# Check for GitHub Tokens
if echo "$DIFF" | grep -E '^[+]' | grep -E -q '(gh[pousr]_[A-Za-z0-9_]{36}|github_pat_[A-Za-z0-9_]{82})'; then
    echo "\u274C COMMIT BLOCKED: Potential GitHub Personal Access Token found in staged changes!"
    echo "Please remove the token before committing."
    exit 1
fi

# Check for Stripe Secret Keys
if echo "$DIFF" | grep -E '^[+]' | grep -E -q '(sk|rk)_(live|test)_[0-9a-zA-Z]{24}'; then
    echo "\u274C COMMIT BLOCKED: Stripe Secret Key found in staged changes!"
    exit 1
fi

# Check for Private Keys
if echo "$DIFF" | grep -E '^[+]' | grep -E -q '-----BEGIN (RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----'; then
    echo "\u274C COMMIT BLOCKED: Unencrypted Private Key found in staged changes!"
    exit 1
fi

echo "\u2705 [Secret Leak Detector] Staged changes clean. Proceeding with commit."
exit 0
`;try{return I.writeFileSync(r,o,{mode:493}),{success:!0,message:`Pre-commit hook successfully installed to ${r}`}}catch(i){return{success:!1,message:`Failed to write hook file: ${i}`}}}};var C;function se(t){C=c.window.createOutputChannel("Secret Leak Detector"),t.subscriptions.push(C),C.appendLine("\u{1F510} [Secret Leak Detector] Extension activated.");let e=new F;t.subscriptions.push(e),t.subscriptions.push(c.languages.registerCodeActionsProvider({scheme:"file"},new A(e),{providedCodeActionKinds:A.providedCodeActionKinds}));let r=new R,o=new L;c.window.registerTreeDataProvider("secret-leak-detector.findingsView",r),c.window.registerTreeDataProvider("secret-leak-detector.overviewView",o);let i=c.workspace.workspaceFolders?.[0],s=i?i.uri.fsPath:process.cwd(),d=new M(s);e.onFindingsChanged(n=>{r.updateFindings(n),o.update(n.length,!0),w.currentPanel&&w.currentPanel.updateFindings(n)});let l=c.workspace.getConfiguration("secretLeakDetector");l.get("enableRealtimeScanning",!0)&&(c.window.activeTextEditor&&e.scanDocument(c.window.activeTextEditor.document),t.subscriptions.push(c.workspace.onDidSaveTextDocument(n=>{e.scanDocument(n)})),t.subscriptions.push(c.workspace.onDidOpenTextDocument(n=>{e.scanDocument(n)})),t.subscriptions.push(c.workspace.onDidCloseTextDocument(n=>{e.removeDocument(n.uri)}))),t.subscriptions.push(c.commands.registerCommand("secret-leak-detector.scanWorkspace",async()=>{await c.window.withProgress({location:c.ProgressLocation.Notification,title:"\u{1F510} Scanning workspace for secret leaks...",cancellable:!1},async n=>{let g=`{${l.get("excludeGlobs",[]).join(",")}}`,f=await c.workspace.findFiles("**/*",g,1e3),u=[],x=0;for(let T of f)try{let b=await c.workspace.openTextDocument(T),D=e.scanDocument(b);u.push(...D),x++}catch{}if(u.length===0)c.window.showInformationMessage(`\u2705 Scan complete: Scanned ${x} files. No secrets or credentials detected!`);else{let T=u.filter(b=>b.risk==="CRITICAL").length;c.window.showErrorMessage(`\u{1F6A8} Found ${u.length} leaked secret(s) (${T} Critical)! Commits may be blocked.`,"Open Dashboard","View Findings").then(b=>{b==="Open Dashboard"?c.commands.executeCommand("secret-leak-detector.openDashboard"):b==="View Findings"&&c.commands.executeCommand("workbench.view.extension.secret-leak-detector-sidebar")})}})})),t.subscriptions.push(c.commands.registerCommand("secret-leak-detector.scanStaged",async()=>{C.clear(),C.appendLine("\u{1F510} [Secret Leak Detector] Scanning Git staged changes..."),C.show(!0);let n=await d.scanStagedChanges();if(n.length===0)C.appendLine("\u2705 All staged changes are clean! No credentials detected."),c.window.showInformationMessage("\u2705 Git staged changes are safe to commit.");else{let p=d.formatTerminalBlockedMessage(n);C.appendLine(p),c.window.showErrorMessage(`\u274C COMMIT BLOCKED: ${n.length} secret(s) detected in staged changes!`,"Open Dashboard","View Output").then(g=>{g==="Open Dashboard"&&w.createOrShow(t.extensionUri,n)})}})),t.subscriptions.push(c.commands.registerCommand("secret-leak-detector.openDashboard",()=>{w.createOrShow(t.extensionUri,e.getAllFindings())})),t.subscriptions.push(c.commands.registerCommand("secret-leak-detector.installGitHook",async()=>{let n=await d.installPreCommitHook();n.success?c.window.showInformationMessage(`\u{1F6E1}\uFE0F ${n.message}`):c.window.showErrorMessage(`Failed to install hook: ${n.message}`)})),t.subscriptions.push(c.commands.registerCommand("secret-leak-detector.remediateFinding",async(n,p,g)=>{await A.executeRemediation(n,p,g)})),t.subscriptions.push(c.commands.registerCommand("secret-leak-detector.clearFindings",()=>{e.clear(),c.window.showInformationMessage("Secret Leak Detector: All findings cleared.")})),d.isGitRepo().then(n=>{o.update(0,n)})}function re(){C&&C.dispose()}0&&(module.exports={activate,deactivate});
