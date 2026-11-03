"use strict";var tn=Object.create;var Re=Object.defineProperty;var nn=Object.getOwnPropertyDescriptor;var sn=Object.getOwnPropertyNames;var on=Object.getPrototypeOf,rn=Object.prototype.hasOwnProperty;var an=(t,e)=>{for(var n in e)Re(t,n,{get:e[n],enumerable:!0})},ut=(t,e,n,i)=>{if(e&&typeof e=="object"||typeof e=="function")for(let s of sn(e))!rn.call(t,s)&&s!==n&&Re(t,s,{get:()=>e[s],enumerable:!(i=nn(e,s))||i.enumerable});return t};var D=(t,e,n)=>(n=t!=null?tn(on(t)):{},ut(e||!t||!t.__esModule?Re(n,"default",{value:t,enumerable:!0}):n,t)),cn=t=>ut(Re({},"__esModule",{value:!0}),t);var Bn={};an(Bn,{activate:()=>Dn,deactivate:()=>Mn});module.exports=cn(Bn);var S=D(require("vscode")),q=D(require("path")),F=D(require("fs"));var N=D(require("vscode"));var he=D(require("path")),Wt=D(require("crypto"));var gt=[{id:"aws-access-key",name:"AWS Access Key ID",provider:"Amazon Web Services",pattern:/\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b/g,baseConfidence:98,baseRiskWeight:95,signals:["AWS IAM standard 20-character key prefix (AKIA/ASIA/ABIA/ACCA)","Deterministic uppercase alphanumeric structure","Direct cloud resource control & hijacking capability"],suggestedEnvName:()=>"AWS_ACCESS_KEY_ID",remediationInstructions:["Revoke the exposed Access Key ID immediately in AWS IAM Management Console.","Check AWS CloudTrail logs for unauthorized API calls originated by this key.","Transition to IAM Roles for Amazon EC2 or AWS IAM Identity Center (SSO).","Never store access keys in source code; use AWS_ACCESS_KEY_ID environment variable."]},{id:"aws-secret-key",name:"AWS Secret Access Key",provider:"Amazon Web Services",pattern:/["']?(?:aws_secret_access_key|aws_secret_key|secret_access_key)["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?(?:[\s\r\n;,)}\]]|$)/gi,baseConfidence:94,baseRiskWeight:95,minEntropy:4.1,signals:["Contextual AWS credential parameter match","High-entropy 40-character Base64 payload","Pairs with AWS Access Key for root/IAM API authentication"],suggestedEnvName:()=>"AWS_SECRET_ACCESS_KEY",remediationInstructions:["Rotate the key pair immediately in the AWS IAM Console.","Audit AWS KMS and S3 bucket accesses during exposure window.","Store secrets in AWS Secrets Manager or Parameter Store."]},{id:"github-pat",name:"GitHub Personal Access Token",provider:"GitHub",pattern:/\b(gh[pousr]_[A-Za-z0-9_]{36,255}|github_pat_[A-Za-z0-9_]{82})\b/g,baseConfidence:99,baseRiskWeight:95,signals:["Official GitHub token format prefix (ghp_, gho_, ghu_, ghs_, github_pat_)","Deterministic token structure and length","Permits repository code modification, workflow execution, or release poisoning"],suggestedEnvName:()=>"GITHUB_TOKEN",remediationInstructions:["Revoke token immediately at https://github.com/settings/tokens.","Check GitHub Security Audit Log for unauthorized repository clones or writes.","Use GitHub fine-grained PATs with scoped repository permissions.","Use GitHub Actions secrets rather than personal tokens for CI/CD."]},{id:"google-api-key",name:"Google Cloud / Gemini API Key",provider:"Google Cloud",pattern:/\b(AIza[0-9A-Za-z_-]{34,35})\b/g,baseConfidence:96,baseRiskWeight:90,minEntropy:3.5,signals:["Google standard AIza service key signature","Fixed 39-character alphanumeric structure","Access to Google Cloud Platform APIs and billing services"],suggestedEnvName:()=>"GEMINI_API_KEY",remediationInstructions:["Restrict or delete the API key in Google Cloud Console Credentials page.","Apply API restrictions (e.g. restrict solely to Generative Language API).","Apply HTTP referrer or IP address restrictions.","Store in GEMINI_API_KEY environment variable."]},{id:"google-oauth-token",name:"Google OAuth Access Token",provider:"Google Cloud",pattern:/\b(ya29\.[0-9a-zA-Z_-]{50,150})\b/g,baseConfidence:98,baseRiskWeight:92,minEntropy:4,signals:["Google OAuth bearer access token prefix (ya29.)","Direct user account delegation & Cloud Platform API access"],suggestedEnvName:()=>"GOOGLE_OAUTH_TOKEN",remediationInstructions:["Revoke token via Google Cloud IAM or OAuth2 token revocation endpoint.","Store OAuth refresh tokens securely in credential vaults."]},{id:"openai-api-key",name:"OpenAI API Key",provider:"OpenAI",pattern:/\b(sk-(?:proj|admin|svcacct)-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{20,48})\b/g,baseConfidence:97,baseRiskWeight:92,minEntropy:4,signals:["OpenAI official secret prefix (sk-proj- or sk-)","High Shannon entropy key payload","Direct account credit exhaustion and model theft risk"],suggestedEnvName:()=>"OPENAI_API_KEY",remediationInstructions:["Revoke key at https://platform.openai.com/api-keys.","Verify credit consumption in OpenAI usage dashboard.","Inject credentials using OPENAI_API_KEY environment variable."]},{id:"anthropic-api-key",name:"Anthropic Claude API Key",provider:"Anthropic",pattern:/\b(sk-ant-[A-Za-z0-9_-]{30,})\b/g,baseConfidence:98,baseRiskWeight:92,minEntropy:3.8,signals:["Anthropic official secret token signature (sk-ant-)","High entropy cryptographic token payload","Direct Claude model API billing access"],suggestedEnvName:()=>"ANTHROPIC_API_KEY",remediationInstructions:["Revoke the API key in Anthropic Console.","Generate replacement key with spend limit configured.","Inject via ANTHROPIC_API_KEY environment variable."]},{id:"huggingface-token",name:"Hugging Face Access Token",provider:"Hugging Face",pattern:/\b(hf_[A-Za-z0-9]{34})\b/g,baseConfidence:98,baseRiskWeight:88,minEntropy:3.8,signals:["Hugging Face user access token format (hf_ prefix + 34 chars)","Grants access to gated AI models, private repositories, and inference endpoints"],suggestedEnvName:()=>"HF_TOKEN",remediationInstructions:["Revoke token immediately at https://huggingface.co/settings/tokens.","Audit access logs for unauthorized model downloads.","Inject credentials using the HF_TOKEN environment variable."]},{id:"stripe-secret-key",name:"Stripe Secret Key",provider:"Stripe",pattern:/\b((?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,100})\b/g,baseConfidence:97,baseRiskWeight:96,signals:["Stripe signature prefix (sk_live / rk_live / sk_test)","Financial transaction and customer credit card access","High financial liability and compliance breach"],suggestedEnvName:()=>"STRIPE_SECRET_KEY",remediationInstructions:["Roll API key immediately in Stripe Dashboard > Developers > API keys.","Audit recent transactions and payout bank account modifications.","Never bundle Stripe secret keys in frontend or mobile client builds."]},{id:"slack-bot-token",name:"Slack OAuth / Bot Token",provider:"Slack",pattern:/\b(xox[baprs]-[0-9A-Za-z-]{10,72})\b/g,baseConfidence:95,baseRiskWeight:82,signals:["Slack OAuth bot/user prefix (xoxb/xoxp/xoxa)","Internal company communications and workspace access"],suggestedEnvName:()=>"SLACK_BOT_TOKEN",remediationInstructions:["Revoke token in api.slack.com/apps.","Re-install app with minimal necessary OAuth scopes."]},{id:"slack-webhook",name:"Slack Incoming Webhook URL",provider:"Slack",pattern:/(https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9_]{8,12}\/B[A-Z0-9_]{8,12}\/[A-Za-z0-9_]{24})/g,baseConfidence:98,baseRiskWeight:78,signals:["Slack Incoming Webhook URL structure","Enables unauthorized message spoofing and channel phishing"],suggestedEnvName:()=>"SLACK_WEBHOOK_URL",remediationInstructions:["Delete the exposed webhook URL in Slack App settings.","Generate a new webhook URL and store in SLACK_WEBHOOK_URL."]},{id:"azure-storage-key",name:"Azure Shared Storage Key",provider:"Microsoft Azure",pattern:/["']?(?:AccountKey|azure_secret|azure_key)["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{86,88}==)(?:["';,\s\r\n)}\]]|$)/gi,baseConfidence:93,baseRiskWeight:90,minEntropy:4.2,signals:["Azure storage account key signature (86-88 chars base64 with == padding)","Full administrative access to Azure Blob/Queue/Table storage"],suggestedEnvName:()=>"AZURE_STORAGE_KEY",remediationInstructions:["Regenerate storage key in Azure Portal.","Adopt Azure Managed Identity or Microsoft Entra ID authentication instead."]},{id:"azure-ad-client-secret",name:"Azure Active Directory Client Secret",provider:"Microsoft Azure",pattern:/["']?(?:azure[_-]?(?:client|ad|app)?[_-]?secret|client[_-]?secret)["']?\s*[:=]\s*["']?([a-zA-Z0-9_~.-]{34,44})["']?(?:[\s\r\n;,)}\]]|$)/gi,baseConfidence:90,baseRiskWeight:90,minEntropy:3.8,signals:["Azure AD / Entra ID client secret assignment pattern","Application impersonation and tenant directory access"],suggestedEnvName:()=>"AZURE_CLIENT_SECRET",remediationInstructions:["Revoke and rotate the client secret in Azure App Registrations portal.","Migrate to Managed Identity or Federated Credentials where possible."]},{id:"discord-bot-token",name:"Discord Bot Token",provider:"Discord",pattern:/\b([M-Z][A-Za-z0-9]{23,27}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,38})\b/g,baseConfidence:98,baseRiskWeight:88,signals:["Official Discord bot token format (ID.HMAC.Signature)","Complete bot control, server membership manipulation, and message reading"],suggestedEnvName:()=>"DISCORD_BOT_TOKEN",remediationInstructions:["Reset token in Discord Developer Portal > Bot > Reset Token.","Store in DISCORD_BOT_TOKEN environment variable."]},{id:"telegram-bot-token",name:"Telegram Bot Token",provider:"Telegram",pattern:/\b([0-9]{8,10}:[a-zA-Z0-9_-]{35})\b/g,baseConfidence:96,baseRiskWeight:85,signals:["Telegram Bot API token format (Numeric ID : 35-character secret)","Direct control of Telegram bot communications and webhooks"],suggestedEnvName:()=>"TELEGRAM_BOT_TOKEN",remediationInstructions:["Revoke and reissue the token using Telegram @BotFather (/revoke).","Store in TELEGRAM_BOT_TOKEN environment variable."]},{id:"pypi-api-token",name:"PyPI API Token",provider:"PyPI",pattern:/\b(pypi-[A-Za-z0-9_-]{50,150})\b/g,baseConfidence:99,baseRiskWeight:92,signals:["Official PyPI package index upload token prefix (pypi-)","Supply chain compromise and malicious Python package publication risk"],suggestedEnvName:()=>"PYPI_TOKEN",remediationInstructions:["Revoke the token immediately at https://pypi.org/manage/account/tokens/.","Inspect published package versions for tampering."]},{id:"shopify-access-token",name:"Shopify Admin / Storefront Access Token",provider:"Shopify",pattern:/\b(shp(?:at|ca|pa)_[a-fA-F0-9]{32})\b/g,baseConfidence:98,baseRiskWeight:92,signals:["Official Shopify access token prefix (shpat_, shpca_, shppa_)","E-commerce store data, customer orders, and payment configuration access"],suggestedEnvName:()=>"SHOPIFY_API_KEY",remediationInstructions:["Revoke the token in Shopify Admin > Apps and sales channels.","Audit store access and customer data logs."]},{id:"digitalocean-pat",name:"DigitalOcean Personal Access Token",provider:"DigitalOcean",pattern:/\b(dop_v1_[a-f0-9]{64})\b/g,baseConfidence:99,baseRiskWeight:92,signals:["Official DigitalOcean v1 token format (dop_v1_ prefix + 64 hex characters)","Droplet creation, destruction, and Cloud infrastructure control"],suggestedEnvName:()=>"DIGITALOCEAN_TOKEN",remediationInstructions:["Revoke the token in DigitalOcean Control Panel > API > Tokens.","Check active Droplets and firewall configurations for unauthorized changes."]},{id:"mailgun-api-key",name:"Mailgun Private API Key",provider:"Mailgun",pattern:/\b(key-[0-9a-zA-Z]{32})\b/g,baseConfidence:96,baseRiskWeight:85,signals:["Mailgun standard private API key signature (key- + 32 chars)","Bulk email dispatch and communication channel spoofing"],suggestedEnvName:()=>"MAILGUN_API_KEY",remediationInstructions:["Rotate key in Mailgun Dashboard > API Security.","Store in MAILGUN_API_KEY environment variable."]},{id:"square-access-token",name:"Square Access Token",provider:"Square",pattern:/\b(sq0atp-[0-9A-Za-z_-]{22}|sq0csp-[0-9A-Za-z_-]{43}|EAAA[a-zA-Z0-9_-]{60})\b/g,baseConfidence:97,baseRiskWeight:94,signals:["Square OAuth / production access token prefix (sq0atp-, sq0csp-, EAAA)","Payment processing, merchant account, and customer financial data access"],suggestedEnvName:()=>"SQUARE_ACCESS_TOKEN",remediationInstructions:["Revoke token in Square Developer Dashboard > OAuth settings.","Audit payment ledger and API access history."]},{id:"private-key",name:"Cryptographic Private Key (PEM)",provider:"Cryptography",pattern:/(-----BEGIN (?:[A-Z0-9_-]+ )*PRIVATE KEY(?: BLOCK)?-----(?:(?!-----BEGIN)[\s\S]){1,8192}?-----END (?:[A-Z0-9_-]+ )*PRIVATE KEY(?: BLOCK)?-----)/g,baseConfidence:100,baseRiskWeight:100,signals:["Standard PEM container header and footer","Unencrypted cryptographic private key","Total server impersonation, SSH compromise, or TLS decryption risk"],suggestedEnvName:()=>"PRIVATE_KEY_PATH",remediationInstructions:["Immediately decommission this private key pair.","Remove public key counterpart from all servers authorized_keys.","Never commit private keys to version control; use SSH agents or secret vaults."]},{id:"database-url",name:"Database Connection String with Credentials",provider:"Database",pattern:/\b((?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis):\/\/[^:\s'"@]+:([^@\s'"]+)@([a-zA-Z0-9_.-]+(?::[0-9]+)?(?:\/[^\s'"`;]*)?))/gi,baseConfidence:92,baseRiskWeight:88,minEntropy:3.2,signals:["Database connection URL containing embedded user:password credentials","Direct data exfiltration, deletion, or ransomware risk"],suggestedEnvName:()=>"DATABASE_URL",remediationInstructions:["Rotate the database user password immediately on the database server.","Migrate connection string to DATABASE_URL environment variable.","Enable SSL/TLS requirement and VPC network access controls."]},{id:"url-credentials",name:"URL with Embedded Credentials",provider:"Generic Credential",pattern:/\b(https?:\/\/[^:\s'"\/?#@]+:([^@\s'"\/?#]+)@([a-zA-Z0-9_.-]+(?::[0-9]+)?(?:\/[^\s'"`;]*)?))/gi,baseConfidence:90,baseRiskWeight:85,minEntropy:3,signals:["HTTP/HTTPS URL containing embedded user:password or user:token credentials","Authentication credential transmission in URL plain text"],suggestedEnvName:()=>"API_ENDPOINT_URL",remediationInstructions:["Remove credentials from URL; pass authentication in Authorization headers.","Rotate exposed password or access token immediately."]},{id:"bearer-token",name:"Authorization Bearer Token",provider:"Auth / Identity",pattern:/["']?(?:Authorization|auth)["']?\s*[:=]\s*["']?Bearer\s+([A-Za-z0-9_.~+/-]{20,255})["']?/gi,baseConfidence:92,baseRiskWeight:85,minEntropy:3.5,signals:["HTTP Authorization header with static Bearer token literal","API session impersonation and service authentication bypass"],suggestedEnvName:()=>"AUTH_TOKEN",remediationInstructions:["Revoke the exposed bearer token.","Inject bearer tokens dynamically from environment variables."]},{id:"jwt-token",name:"JSON Web Token (JWT)",provider:"Auth / Identity",pattern:/\b(ey[A-Za-z0-9_-]{15,}\.ey[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{10,})\b/g,baseConfidence:88,baseRiskWeight:75,minEntropy:4.1,signals:["Header.Payload.Signature Base64 tripartite JWT structure","Authentication session hijacking and privilege escalation"],suggestedEnvName:t=>t?.toUpperCase()||"AUTH_TOKEN",remediationInstructions:["Invalidate active sessions / revoke refresh token family in identity provider.","Never hardcode tokens in client or backend source repositories."]},{id:"gitlab-pat",name:"GitLab Personal Access Token",provider:"GitLab",pattern:/\b(glpat-[0-9a-zA-Z_-]{20,40})\b/g,baseConfidence:98,baseRiskWeight:90,signals:["GitLab personal access token prefix (glpat-)","Repository read/write and CI/CD control"],suggestedEnvName:()=>"GITLAB_TOKEN",remediationInstructions:["Revoke token in GitLab User Settings > Access Tokens.","Store in GITLAB_TOKEN environment variable."]},{id:"npm-access-token",name:"npm Access Token",provider:"npm",pattern:/\b(npm_[A-Za-z0-9]{36})\b/g,baseConfidence:99,baseRiskWeight:92,signals:["npm official access token prefix (npm_)","Package publication and account takeover capability"],suggestedEnvName:()=>"NPM_TOKEN",remediationInstructions:["Revoke token immediately at https://www.npmjs.com/settings/tokens.","Store in NPM_TOKEN environment variable."]},{id:"sendgrid-api-key",name:"SendGrid API Key",provider:"SendGrid",pattern:/\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b/g,baseConfidence:99,baseRiskWeight:85,signals:["SendGrid standard tripartite API key (SG.<22>.<43>)","Email spoofing and communication channel hijacking risk"],suggestedEnvName:()=>"SENDGRID_API_KEY",remediationInstructions:["Revoke key in SendGrid dashboard Settings > API Keys.","Store in SENDGRID_API_KEY environment variable."]},{id:"twilio-api-key",name:"Twilio Auth Token / API Secret",provider:"Twilio",pattern:/\b(SK[0-9a-fA-F]{32})\b|["']?(?:twilio[a-z0-9_-]*(?:auth_?token|api_?secret|secret)|(?:auth_?token|api_?secret))["']?\s*[:=]\s*["']?([0-9a-fA-F]{32})["']?(?:[\s\r\n;,)}\]]|$)/gi,baseConfidence:95,baseRiskWeight:90,minEntropy:3.5,signals:["Twilio Auth Token, API Key SID (SK...), or API Secret assignment","32-character hexadecimal secret token","Telephony API and SMS billing access"],suggestedEnvName:()=>"TWILIO_AUTH_TOKEN",remediationInstructions:["Rotate token in Twilio Console.","Store in TWILIO_AUTH_TOKEN environment variable."]},{id:"password-assignment",name:"Password in Source Code",provider:"Generic Credential",pattern:/["']?(?:password|passwd|pwd|db_password|db_pass)["']?\s*[:=]\s*["']?(?!(?:password|passwordRequired|required|required_field|true|false|null|undefined|string|default|changeme|placeholder|example|admin|test)(?:["'\r\n\s#;,)}\]]|$))([^"'\r\n\s#;,]{8,64})["']?/gi,baseConfidence:82,baseRiskWeight:80,minEntropy:2.8,signals:["Hard-coded password assignment in code, .env, or YAML","Credential exposure in plain text"],suggestedEnvName:()=>"PASSWORD",remediationInstructions:["Rotate password immediately.","Store password in an environment variable or secrets manager.","Never commit plain passwords to version control."]},{id:"generic-api-key",name:"Generic API Secret Assignment",provider:"Generic Credential",pattern:/["']?(?:api_?key|secret_?key|auth_?token|client_?secret|access_?token|private_?key|jwt_?secret)["']?\s*[:=]\s*["']?(?!(?:process\.env|import\.meta\.env|os\.environ|ENV)\b)([A-Za-z0-9_.~/+=-]{20,90})["']?(?:[\s\r\n;,)}\]]|$)/gi,baseConfidence:80,baseRiskWeight:70,minEntropy:3.5,signals:["Sensitive identifier keyword assignment in code, .env, or YAML","High Shannon entropy string literal"],suggestedEnvName:t=>t?t.toUpperCase():"API_KEY",remediationInstructions:["Identify corresponding API provider and rotate credential.","Migrate credential to local .env file (ensure .env is in .gitignore)."]}];var Q=D(require("path")),dn=[/api[_-]?key/i,/secret[_-]?key/i,/access[_-]?token/i,/auth[_-]?token/i,/private[_-]?key/i,/client[_-]?secret/i,/password/i,/credential/i,/session[_-]?token/i,/bearer/i,/aws[_-]?(?:access|secret)/i,/stripe[_-]?(?:secret|key)/i,/github[_-]?(?:token|pat)/i,/slack[_-]?token/i,/db[_-]?pass(?:word)?/i],ln=[/placeholder/i,/mock/i,/dummy/i,/fake/i,/sample/i,/test[_-]?(?:key|token|id)/i,/demo/i,/insert[_-]?here/i];function pn(t,e){if(e){let n=Q.relative(e,t);if(!n.startsWith("..")&&!Q.isAbsolute(n))return n.replace(/\\/g,"/")}return Q.isAbsolute(t)?Q.basename(t):t.replace(/\\/g,"/")}function ft(t,e){let n=pn(t,e).toLowerCase(),i=Q.basename(t).toLowerCase(),s=Q.extname(t).toLowerCase(),o=/(?:^|\/)(?:tests?|specs?|__tests__|__mocks__|fixtures|mocks)\//i.test(n)||/[._-](?:test|spec)\.[a-z0-9]+$/i.test(i)||/^(?:test|spec)\.[a-z0-9]+$/i.test(i),r=/(?:^|\/)(?:docs|doc|documentation|tutorials|guides)\/|readme\.md|contributing\.md|changelog\.md/i.test(n),a=/(?:^|\/)(?:example|sample|\.example|\.sample)/i.test(n)||/[._-](?:example|sample)\.[a-z0-9]+$/i.test(i),c=/^\.env(?:\.[a-z0-9]+)?$/.test(i)||/(?:^|\/)(?:config|settings|k8s|helm|deploy|tfvars)\//i.test(n)||/(?:^|[._-])(?:config|settings|secret|credential|database|deploy)\.[a-z0-9]+$/i.test(i)||[".env",".yaml",".yml",".json",".toml",".ini",".tf"].includes(s),d=/^\.env/.test(i)||/(?:secret|credential|id_rsa|private_key|keypair|auth_config)/i.test(i);return{fileExtension:s,isConfig:c,isTest:o,isDoc:r,isSensitiveName:d,isExampleOrSample:a}}function Ge(t,e){let n=t[e]||"",i=[];for(let m=Math.max(0,e-3);m<e;m++)i.push(t[m]);let s=[];for(let m=e+1;m<Math.min(t.length,e+4);m++)s.push(t[m]);let o,r=n.match(/(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*[:=]/),a=n.match(/["']?([a-zA-Z0-9_$-]+)["']?\s*[:=]/);r?o=r[1]:a&&(o=a[1]);let c=o?dn.some(m=>m.test(o)):!1,d=o?ln.some(m=>m.test(o)):!1,u=/[:=]/.test(n),p=/(?:process\.env|os\.environ|dotenv|config|getenv)/i.test(n),l=/(?:authorization|bearer|x-api-key)/i.test(n),f=/^\s*(?:\/\/|#|\/\*|\*|--)/.test(n);return{inferredVariable:o,isSensitiveIdentifier:c,isBenignIdentifier:d,isAssignment:u,isEnvOrConfigAccess:p,isHeaderOrBearer:l,isInComment:f,surroundingBefore:i,matchedLine:n,surroundingAfter:s}}var Ue=D(require("fs")),Ve=D(require("path")),Te=/(?:api_?key|secret|token|password|auth|credential|access_?key|private_?key)/i,mt=/(?:console\.(?:log|warn|error|info|debug)|logger\.|print\(|logging\.)/i,oe=null;function je(){if(oe)return oe;try{let t=Ve.join(__dirname,"ast-parser.js");if(Ue.existsSync(t))return oe=require(t),oe}catch{}try{let t=Ve.join(__dirname,"../../dist/ast-parser.js");if(Ue.existsSync(t))return oe=require(t),oe}catch{}try{return oe=require("typescript"),oe}catch{}return null}function Ze(t,e){let n=je();if(!n||!(!e||/\.[jt]sx?$|\.m[jt]s$|\.c[jt]s$/i.test(e)))return null;try{return n.createSourceFile(e||"eval_target.tsx",t,n.ScriptTarget.Latest,!0,n.ScriptKind.TSX)}catch{return null}}function qe(t,e,n,i,s){let o=t[e]||"";if(je()&&(!n||/\.[jt]sx?$|\.m[jt]s$|\.c[jt]s$/i.test(n)))if(i){let d=ht(i,s!==void 0?s:e);if(d)return d}else{let c,d;if(t.length>60){let p=Math.max(0,e-30),l=Math.min(t.length,e+30);c=t.slice(p,l).join(`
`),d=e-p}else c=t.join(`
`),d=e;let u=un(c,d);if(u)return u}return gn(o)}function ht(t,e){try{let c=function(d){if(!a&&!(d.pos>r||d.end<o)&&(i.forEachChild(d,c),!a)){if(d.kind===i.SyntaxKind.BinaryExpression&&(d.operatorToken.kind===i.SyntaxKind.BarBarToken||d.operatorToken.kind===i.SyntaxKind.QuestionQuestionToken)){let u=d.left.getText(t);if(u.includes("process.env")||u.includes("env")||u.toLowerCase().includes("key")){a={variablePath:u,isSensitiveProperty:Te.test(u),isEnvFallback:!0,isAuthorizationHeader:!1,isLoggingCall:!1,scopeType:"ENV_FALLBACK"};return}}if(d.kind===i.SyntaxKind.PropertyAssignment){let u=d.name.getText(t),p=u,l=d.parent;for(;l;)l.kind===i.SyntaxKind.PropertyAssignment&&l.name?p=`${l.name.getText(t)}.${p}`:l.kind===i.SyntaxKind.VariableDeclaration&&l.name&&(p=`${l.name.getText(t)}.${p}`),l=l.parent;let f=Te.test(p),m=/authorization|bearer|x-api-key/i.test(u);a={variablePath:p,isSensitiveProperty:f,isEnvFallback:!1,isAuthorizationHeader:m,isLoggingCall:!1,scopeType:m?"HEADER":"OBJECT_PROPERTY"};return}if(d.kind===i.SyntaxKind.CallExpression){let u=d.expression.getText(t);if(mt.test(u)){a={variablePath:u,isSensitiveProperty:!1,isEnvFallback:!1,isAuthorizationHeader:!1,isLoggingCall:!0,scopeType:"FUNCTION_ARG"};return}}if(d.kind===i.SyntaxKind.VariableDeclaration){let u=d.name.getText(t);a={variablePath:u,isSensitiveProperty:Te.test(u),isEnvFallback:!1,isAuthorizationHeader:!1,isLoggingCall:!1,scopeType:"VARIABLE_DECLARATION"};return}}};var n=c;let i=je();if(!i)return null;let s=t.getLineStarts();if(e>=s.length)return null;let o=s[e],r=e+1<s.length?s[e+1]-1:t.text?.length||0,a=null;return c(t),a}catch{return null}}function un(t,e){let n=Ze(t);return n?ht(n,e):null}function gn(t){let e=mt.test(t),n=/(?:process\.env\.[A-Za-z0-9_]+|os\.(?:getenv|environ\.get)\([^)]+\))\s*(?:\|\||\?\?)\s*["'][^"']+["']/.test(t),i=/(?:authorization|x-api-key|bearer)\s*[:=]/i.test(t),s=t.match(/([a-zA-Z0-9_$.]+)\s*[:=]\s*["'][^"']+["']/)||t.match(/["']([a-zA-Z0-9_.]+)["']\s*:\s*["'][^"']+["']/),o,r=!1;s&&(o=s[1],r=Te.test(o));let a="UNKNOWN";return n?a="ENV_FALLBACK":i?a="HEADER":o&&o.includes(".")?a="OBJECT_PROPERTY":o?a="VARIABLE_DECLARATION":e&&(a="FUNCTION_ARG"),{variablePath:o,isSensitiveProperty:r,isEnvFallback:n,isAuthorizationHeader:i,isLoggingCall:e,scopeType:a}}function be(t){if(!t||t.length===0)return 0;let e={};for(let s of t)e[s]=(e[s]||0)+1;let n=0,i=t.length;for(let s in e){let o=e[s]/i;n-=o*Math.log2(o)}return Math.round(n*100)/100}function Ye(t){return/^[0-9a-fA-F]+$/.test(t)?{setName:"HEX",baseSize:16}:/^[A-Za-z0-9+/=_-]+$/.test(t)?{setName:"BASE64",baseSize:64}:/^[A-Za-z0-9]+$/.test(t)?{setName:"ALPHANUMERIC",baseSize:62}:/^[\x20-\x7E]+$/.test(t)?{setName:"ASCII_PRINTABLE",baseSize:95}:{setName:"SPECIAL",baseSize:128}}function vt(t){if(!t||t.length===0)return 0;let e=be(t),{baseSize:n}=Ye(t),i=Math.log2(n);if(i<=0)return 0;let s=Math.min(1,e/i);return Math.round(s*100)/100}var fn=[/\bplaceholder\b/i,/\byour[_-]?(?:api)?[_-]?key\b/i,/\byour[_-]?secret\b/i,/\byour[_-]?token\b/i,/\binsert[_-]?here\b/i,/\breplace[_-]?me\b/i,/\benter[_-]?your\b/i,/\bchange[_-]?me\b/i,/\bdummy\b/i,/\bfake[_-]?token\b/i,/xxxx+/i,/\btest[_-]?value\b/i,/AKIAIOSFODNN7EXAMPLE/i,/wJalrXUtnFEMI\/K7MDENG\/bPxRfiCYEXAMPLEKEY/i,/^123456789[0-9]*$/,/^abcdef[a-z0-9]*$/i,/00000000[0-9]*/,/sk_live_example/i,/ghp_example/i,/:\/\/[^:]+:(?:password|secret|changeme|pass|admin|test|postgres|root)@(?:localhost|127\.0\.0\.1)(?::\d+)?\b/i,/:\/\/(?:postgres|root):(postgres|root)@(?:localhost|127\.0\.0\.1)(?::\d+)?\b/i],mn=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,hn=/^(?:mock|dummy|placeholder|fake|sample)_(?:key|token|secret|password|pwd|cred)$/i;function St(t,e,n,i="Generic Credential"){let s=i.startsWith("Generic");if(/(?:process\.env|import\.meta\.env|os\.environ|ENV[\[\.])/.test(t))return{isFalsePositive:!0,reason:"Environment variable lookup expression, not a hard-coded credential literal",confidencePenalty:100};let o=/^(?:this|self|window|global|req|request|headers|config|options|ctx|context|env|process)\.[a-zA-Z0-9_$.]+/i.test(t)||/^[a-zA-Z_$][a-zA-Z0-9_$]*(?:\.[a-zA-Z_$][a-zA-Z0-9_$]*)+$/.test(t)&&!t.startsWith("ey")&&!t.startsWith("ya29.");if(s&&o)return{isFalsePositive:!0,reason:"Property access or object path expression, not a hard-coded credential literal",confidencePenalty:100};if(/^(?:passwordRequired|required_field|required|optional|placeholder|changeme|default|test|dummy|example|string|undefined|null)$/i.test(t))return{isFalsePositive:!0,reason:"Common non-secret schema or form attribute value",confidencePenalty:100};for(let a of fn)if(a.test(t))return{isFalsePositive:!0,reason:`Matched known documentation/placeholder pattern: ${a.source}`,confidencePenalty:100};if(e&&hn.test(e)&&!(t.startsWith("AKIA")||t.startsWith("ASIA")||t.startsWith("ghp_")||t.startsWith("gho_")||t.startsWith("ghu_")||t.startsWith("ghs_")||t.startsWith("ghr_")||t.startsWith("github_pat_")||t.startsWith("glpat-")||t.startsWith("sk_live_")||t.startsWith("rk_live_")||t.startsWith("xoxb-")||t.startsWith("xoxp-")||t.startsWith("xoxa-")||t.startsWith("xoxr-")||t.startsWith("pypi-")||t.startsWith("dop_v1_")||t.startsWith("shpat_")||t.startsWith("shpca_")||t.startsWith("shppa_")||t.startsWith("ya29.")||t.startsWith("key-")||t.startsWith("sq0atp-")||t.startsWith("sq0csp-")||/^SK[0-9a-fA-F]{32}$/.test(t)||t.includes("-----BEGIN")||t.length>=14&&be(t)>=3.6))return{isFalsePositive:!0,reason:`Variable identifier indicates placeholder: ${e}`,confidencePenalty:100};let r=new Set(t.split("")).size;if(t.length>=10&&r<=3)return{isFalsePositive:!0,reason:"Low character diversity (repetitive filler characters)",confidencePenalty:95};if(mn.test(t)&&!e?.match(/secret|token|api_?key/i))return{isFalsePositive:!0,reason:"Standard UUID identifier without credential context",confidencePenalty:90};if(n){let a=/(?:docs|documentation|tutorials|guides)\/|readme\.md/i.test(n);if(/(?:example|sample|\.example|\.sample)/i.test(n)&&/example|your_/i.test(t))return{isFalsePositive:!0,reason:"Sample configuration value inside template/example file",confidencePenalty:90};if(a&&!t.startsWith("ghp_")&&!t.startsWith("AKIA"))return{isFalsePositive:!1,confidencePenalty:25}}return{isFalsePositive:!1,confidencePenalty:0}}function yt(t){if(!/^(AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}$/.test(t))return{isValid:!1,confidenceBonus:0,reason:"Invalid AWS key length or character set"};let e=t.substring(0,4);return{isValid:!0,confidenceBonus:10,reason:{AKIA:"Standard permanent IAM user access key",ASIA:"Temporary STS session access key",ABIA:"AWS Backup access key",ACCA:"AWS CodeCommit access key"}[e]||"Valid AWS Access Key ID structure"}}function bt(t){let e=/^sk_live_[0-9a-zA-Z]{24,100}$/.test(t)||/^rk_live_[0-9a-zA-Z]{24,100}$/.test(t),n=/^sk_test_[0-9a-zA-Z]{24,100}$/.test(t)||/^rk_test_[0-9a-zA-Z]{24,100}$/.test(t);return!e&&!n?{isValid:!1,confidenceBonus:0,reason:"Does not match official Stripe secret key format"}:{isValid:!0,confidenceBonus:e?12:5,reason:e?"Production live Stripe Secret Key":"Stripe Test API key"}}function kt(t){return/^ghp_[A-Za-z0-9_]{36}$/.test(t)?{isValid:!0,confidenceBonus:12,reason:"GitHub Personal Access Token (Classic)"}:/^gho_[A-Za-z0-9_]{36}$/.test(t)?{isValid:!0,confidenceBonus:10,reason:"GitHub OAuth Access Token"}:/^ghs_[A-Za-z0-9_]{36}$/.test(t)?{isValid:!0,confidenceBonus:10,reason:"GitHub Server-to-server token"}:/^github_pat_[A-Za-z0-9_]{82}$/.test(t)?{isValid:!0,confidenceBonus:15,reason:"GitHub Fine-Grained Personal Access Token"}:{isValid:!1,confidenceBonus:0,reason:"Invalid GitHub token prefix or length"}}function Et(t){let e=t.split(".");if(e.length!==3)return{isValid:!1,confidenceBonus:0,reason:"Not a 3-part dot-separated JWT"};try{let n=Buffer.from(e[0],"base64url").toString("utf8"),i=JSON.parse(n);if(i&&typeof i=="object"&&i.alg)return{isValid:!0,confidenceBonus:15,reason:`Valid JWT structure with signature algorithm: ${i.alg}`}}catch{}return{isValid:!1,confidenceBonus:0,reason:"Malformed JWT header JSON payload"}}function At(t){try{let e=new URL(t);if(!["postgres:","postgresql:","mysql:","mongodb:","mongodb+srv:","redis:"].includes(e.protocol))return{isValid:!1,confidenceBonus:0,reason:"Unsupported database protocol scheme"};if(e.password&&e.password.length>0)return{isValid:!0,confidenceBonus:12,reason:`Database connection string containing credentials for user '${e.username||"default"}'`}}catch{let e=/^(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis):\/\/[^:\s'"]+:([^\s'"]+)@([a-zA-Z0-9_.-]+(?::[0-9]+)?\/[^\s'"`;]*)/i,n=t.match(e);if(n&&n[1])return{isValid:!0,confidenceBonus:10,reason:"Database connection URI structure matched with embedded password"}}return{isValid:!1,confidenceBonus:0,reason:"Invalid database connection URL structure"}}function xt(t){return/^sk-proj-[A-Za-z0-9_-]{48,}$/.test(t)?{isValid:!0,confidenceBonus:15,reason:"Valid OpenAI Project API Key format"}:/^sk-admin-[A-Za-z0-9_-]{48,}$/.test(t)?{isValid:!0,confidenceBonus:15,reason:"Valid OpenAI Admin/Organization API Key format"}:/^sk-svcacct-[A-Za-z0-9_-]{48,}$/.test(t)?{isValid:!0,confidenceBonus:15,reason:"Valid OpenAI Service Account Key format"}:/^sk-[A-Za-z0-9]{32,48}$/.test(t)?{isValid:!0,confidenceBonus:10,reason:"Valid OpenAI Standard/Legacy API Key format"}:{isValid:!1,confidenceBonus:0,reason:"Invalid OpenAI API key structure"}}function wt(t){return/^sk-ant-[A-Za-z0-9_-]{40,}$/.test(t)?{isValid:!0,confidenceBonus:15,reason:"Valid Anthropic Claude API Key format"}:{isValid:!1,confidenceBonus:0,reason:"Invalid Anthropic API key format"}}function Ct(t){return/^AIza[0-9A-Za-z_-]{35}$/.test(t)?{isValid:!0,confidenceBonus:12,reason:"Valid Google Cloud / Gemini AIza service key signature"}:{isValid:!1,confidenceBonus:0,reason:"Invalid Google Cloud API key format"}}function It(t){return/^xox[baprs]-[0-9A-Za-z-]{10,72}$/.test(t)?{isValid:!0,confidenceBonus:12,reason:`Valid Slack ${t.startsWith("xoxb")?"Bot Token":t.startsWith("xoxp")?"User Token":"OAuth Token"} signature`}:{isValid:!1,confidenceBonus:0,reason:"Invalid Slack token structure"}}function _t(t){return/^hf_[A-Za-z0-9]{34}$/.test(t)?{isValid:!0,confidenceBonus:12,reason:"Valid Hugging Face User Access Token format"}:{isValid:!1,confidenceBonus:0,reason:"Invalid Hugging Face token structure"}}function Rt(t){return/^[A-Za-z0-9/+=]{40}$/.test(t)?{isValid:!0,confidenceBonus:12,reason:"Valid 40-character AWS Secret Access Key Base64 format"}:{isValid:!1,confidenceBonus:0,reason:"Invalid AWS Secret Access Key format"}}function Tt(t){return/^https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9_]{8,12}\/B[A-Z0-9_]{8,12}\/[A-Za-z0-9_]{24}$/.test(t)?{isValid:!0,confidenceBonus:15,reason:"Valid Slack Incoming Webhook URL structure"}:{isValid:!1,confidenceBonus:0,reason:"Invalid Slack Incoming Webhook URL"}}function Lt(t){return/^[A-Za-z0-9/+=]{86,88}==$/.test(t)?{isValid:!0,confidenceBonus:12,reason:"Valid Azure Storage Account Key Base64 format with padding"}:{isValid:!1,confidenceBonus:0,reason:"Invalid Azure Storage Key format"}}function Ot(t){let e=/-----BEGIN (?:[A-Z0-9_-]+ )*PRIVATE KEY(?: BLOCK)?-----/.test(t),n=/-----END (?:[A-Z0-9_-]+ )*PRIVATE KEY(?: BLOCK)?-----/.test(t);return e&&n?{isValid:!0,confidenceBonus:20,reason:"Valid Cryptographic Private Key PEM block container"}:{isValid:!1,confidenceBonus:0,reason:"Incomplete or malformed PEM key container"}}function Je(t,e,n,i,s,o){let r=[],a=t.baseConfidence;r.push({signal:"KNOWN_PATTERN_MATCH",description:`Matched recognized credential signature for ${t.provider} (${t.name})`,confidenceImpact:0,details:{ruleId:t.id,provider:t.provider}});let c=be(e),d=vt(e),{setName:u}=Ye(e);if(t.minEntropy&&c<t.minEntropy?(a=Math.max(10,a-30),r.push({signal:"LOW_ENTROPY",description:`Low entropy score: ${c} bits/char below minimum threshold of ${t.minEntropy}`,confidenceImpact:-30,details:{shannonEntropy:c,minEntropy:t.minEntropy}})):c>=4.5?(a=Math.min(100,a+5),r.push({signal:"HIGH_ENTROPY",description:`Cryptographic entropy: ${c} bits/char (${u} set), indicates non-human randomness`,confidenceImpact:5,details:{shannonEntropy:c,normalizedEntropy:d,characterSet:u}})):c>=3.4?r.push({signal:"MODERATE_ENTROPY",description:`Moderate entropy: ${c} bits/char (${u} set)`,confidenceImpact:0,details:{shannonEntropy:c,normalizedEntropy:d,characterSet:u}}):(a=Math.max(10,a-15),r.push({signal:"LOW_ENTROPY",description:`Low entropy score: ${c} bits/char (${u} set)`,confidenceImpact:-15,details:{shannonEntropy:c,normalizedEntropy:d,characterSet:u}})),i.isSensitiveIdentifier||o?.isSensitiveProperty){let h=o?.variablePath||i.inferredVariable||"credential";a=Math.min(100,a+10),r.push({signal:"SENSITIVE_IDENTIFIER",description:`Assigned to sensitive identifier / property: '${h}'`,confidenceImpact:10,details:{identifier:h}})}else i.isBenignIdentifier&&(a=Math.max(10,a-25),r.push({signal:"BENIGN_IDENTIFIER",description:`Identifier name indicates mock or sample value: '${i.inferredVariable}'`,confidenceImpact:-25,details:{identifier:i.inferredVariable}}));o?.isEnvFallback&&(a=Math.min(100,a+12),r.push({signal:"ENV_FALLBACK_ASSIGNMENT",description:'Hardcoded literal provided as environment variable fallback (e.g. process.env.KEY || "...")',confidenceImpact:12})),o?.isAuthorizationHeader&&(a=Math.min(100,a+10),r.push({signal:"AUTHORIZATION_HEADER",description:"Passed in HTTP Authorization or Bearer token header context",confidenceImpact:10})),(n.isConfig||n.isSensitiveName)&&(a=Math.min(100,a+8),r.push({signal:"PRODUCTION_CONFIG_FILE",description:`Located in configuration or secret storage file (${n.fileExtension})`,confidenceImpact:8,details:{isConfig:n.isConfig,extension:n.fileExtension}})),n.isTest&&(a=Math.max(20,a-20),r.push({signal:"TEST_FILE_PENALTY",description:"Found inside test/mock directory structure",confidenceImpact:-20})),n.isDoc&&(a=Math.max(20,a-25),r.push({signal:"DOCUMENTATION_PENALTY",description:"Found inside documentation or markdown guide",confidenceImpact:-25}));let p;t.id==="aws-access-key"?p=yt(e):t.id==="aws-secret-key"?p=Rt(e):t.id==="stripe-secret-key"?p=bt(e):t.id==="github-pat"?p=kt(e):t.id==="jwt-token"?p=Et(e):t.id==="database-url"?p=At(e):t.id==="openai-api-key"?p=xt(e):t.id==="anthropic-api-key"?p=wt(e):t.id==="google-api-key"?p=Ct(e):t.id==="slack-bot-token"?p=It(e):t.id==="slack-webhook"?p=Tt(e):t.id==="azure-storage-key"?p=Lt(e):t.id==="huggingface-token"?p=_t(e):t.id==="private-key"&&(p=Ot(e)),p&&p.isValid&&(a=Math.min(100,a+p.confidenceBonus),r.push({signal:"STRUCTURAL_VALIDATION_PASSED",description:`Structural validation verified: ${p.reason}`,confidenceImpact:p.confidenceBonus}));let l=St(e,i.inferredVariable,s,t.provider);if(l.isFalsePositive)return{confidence:0,evidence:{items:[{signal:"KNOWN_PLACEHOLDER_REJECTED",description:l.reason||"Placeholder value rejected",confidenceImpact:-100}],shannonEntropy:c,normalizedEntropy:d,characterSet:u,surroundingCode:{before:i.surroundingBefore,targetLine:i.matchedLine,after:i.surroundingAfter,inferredVariable:i.inferredVariable},fileContext:{fileExtension:n.fileExtension,isConfig:n.isConfig,isTest:n.isTest,isDoc:n.isDoc,isSensitiveName:n.isSensitiveName,isExampleOrSample:n.isExampleOrSample}},isSuppressed:!0,suppressReason:l.reason};l.confidencePenalty>0&&(a=Math.max(10,a-l.confidencePenalty));let f=Math.max(0,Math.min(100,Math.round(a))),m={items:r,shannonEntropy:c,normalizedEntropy:d,characterSet:u,surroundingCode:{before:i.surroundingBefore,targetLine:i.matchedLine,after:i.surroundingAfter,inferredVariable:i.inferredVariable},fileContext:{fileExtension:n.fileExtension,isConfig:n.isConfig,isTest:n.isTest,isDoc:n.isDoc,isSensitiveName:n.isSensitiveName,isExampleOrSample:n.isExampleOrSample}};return{confidence:f,evidence:m,isSuppressed:!1}}function Xe(t,e,n,i){let s=[],o=0,r=Math.min(40,Math.round(t.baseRiskWeight/100*40));o+=r,s.push({factor:"CREDENTIAL_SEVERITY",weight:40,scoreContribution:r,explanation:`${t.provider} ${t.name} has high inherent privilege capability`});let a=Math.round(e/100*25);o+=a,s.push({factor:"CONFIDENCE_LEVEL",weight:25,scoreContribution:a,explanation:`Multi-signal verification confidence is ${e}%`});let c=5,d="Standard source code file";n.isConfig||n.isSensitiveName?(c=15,d="Located in sensitive deployment / environment configuration"):n.isTest?(c=0,d="Located in test / fixture codebase with reduced operational blast radius"):n.isDoc&&(c=0,d="Located in documentation context"),o+=c,s.push({factor:"STORAGE_ENVIRONMENT",weight:15,scoreContribution:c,explanation:d});let u=5,p="Found in local uncommitted working tree";i&&(i.isRemote===!0?(u=20,p="Pushed to remote repository branch (external exposure risk)"):i.isPresentInHistory===!0?(u=16,p=`Committed to Git history across ${i.branches.length||1} branch(es) (${i.exposureDurationDays} days exposure)`):i.isPresentInHistory==="UNKNOWN"?(u=16,p="Git history exposure could not be fully verified (conservative risk rating applied)"):i.isPresentInHead===!0?(u=12,p="Committed in current HEAD commit"):i.isPresentInHead==="UNKNOWN"&&(u=12,p="Current HEAD commit exposure could not be fully verified (conservative risk rating applied)")),o+=u,s.push({factor:"EXPOSURE_REACH",weight:20,scoreContribution:u,explanation:p});let l=Math.max(0,Math.min(100,Math.round(o))),f="LOW";l>=76?f="CRITICAL":l>=51?f="HIGH":l>=26?f="MEDIUM":f="LOW";let m=vn(l,i),h=`${f} Risk (${l}/100) \u2014 ${t.name}. ${m.summary}`;return{score:l,tier:f,factors:s,blastRadius:m,summary:h}}function vn(t,e){let n=[],i=Math.round(t*.5),s=e?e.isSecretInWorkingTree==="UNKNOWN"||e.isPresentInWorkingTree==="UNKNOWN"?"UNKNOWN":e.isSecretInWorkingTree===!0||e.isPresentInWorkingTree===!0:!0,o=e?e.isPresentInHistory==="UNKNOWN"?"UNKNOWN":e.isPresentInHistory===!0:!1,r=e?.commitCount??(o?1:0),a=e?.branches||["main"],c=a.length,d=e?e.isRemote==="UNKNOWN"?"UNKNOWN":e.isRemote===!0:!1,u=e?.exposureDurationDays||0;s==="UNKNOWN"?(n.push("Working tree status unverified (conservative exposure assumed)"),i+=15):s&&(n.push("Active working tree contains exposed secret"),i+=15),o==="UNKNOWN"?(n.push("Git history status unverified (conservative exposure assumed)"),i+=20):o&&(n.push(`Git history contains commit records across ${c} branch(es)`),i+=20),d==="UNKNOWN"?(n.push("Remote tracking branch status unverified (conservative exposure assumed)"),i+=20):d&&(n.push("Secret has been synchronized to remote tracking branches"),i+=25),u>7&&(n.push(`Exposure duration exceeds ${u} days without rotation`),i+=10),i=Math.max(0,Math.min(100,i));let p="CONTAINED";i>=75?p="SEVERE":i>=50?p="EXTENSIVE":i>=25?p="MODERATE":p="CONTAINED";let l=`Blast Radius: ${p} (${i}/100) \u2014 ${d===!0?"Remote & history exposure":d==="UNKNOWN"?"Unverified remote tracking risk":o===!0||o==="UNKNOWN"?"Historical commit exposure":"Contained to local working tree"}`;return{level:p,score:i,workingTreeExposed:s,gitHistoryExposed:o,commitCount:r,branchCount:c,branches:a,remoteExposed:d,exposureDurationDays:u,summary:l,factors:n}}var V=D(require("fs")),bn=D(require("child_process")),re=D(require("path")),Nt=D(require("os"));var Ft=D(require("crypto")),Le=D(require("fs")),Pt=D(require("path")),Sn="sld_fingerprint_salt_v1_d8e9f2a1b4c3e7f0";function yn(t,e){if(t)return t;if(process.env.SLD_SALT||process.env.SLD_FINGERPRINT_SALT)return process.env.SLD_SALT||process.env.SLD_FINGERPRINT_SALT;let n=e||process.cwd();try{let i=Pt.join(n,".sld","salt");if(Le.existsSync(i)){let s=Le.readFileSync(i,"utf8").trim();if(s)return s}}catch{}return Sn}function ke(t){if(!t)return"";let e=t.length;if(e<=12)return"\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022";let n=Math.max(2,Math.floor(e*.2)),i=Math.min(4,Math.max(1,Math.floor(n/2))),s=Math.min(3,Math.max(1,n-i)),o=Math.max(6,Math.min(16,e-i-s)),r=t.substring(0,i),a=t.substring(e-s),c="\u2022".repeat(o);return`${r}${c}${a}`}function Qe(t,e,n){let i=yn(e,n),s=t.replace(/\r\n/g,`
`);return Ft.createHmac("sha256",i).update(s).digest("hex").substring(0,16)}function et(t){return t.replace(/\\/g,"\\\\").replace(/"/g,'\\"').replace(/\$/g,"\\$").replace(/\n/g,"\\n").replace(/\r/g,"\\r")}function $t(t,e){switch(re.extname(t).toLowerCase()){case".py":return`os.environ.get("${e}")`;case".go":return`os.Getenv("${e}")`;case".rb":return`ENV['${e}']`;case".php":return`getenv('${e}')`;case".java":case".kt":return`System.getenv("${e}")`;case".rs":return`std::env::var("${e}").unwrap()`;case".sh":case".bash":case".zsh":return`"\${${e}}"`;case".yaml":case".yml":case".toml":case".env":return`\${${e}}`;case".js":case".jsx":case".ts":case".tsx":case".mjs":case".cjs":default:return`process.env.${e}`}}function tt(t,e,n,i,s){let o=t.suggestedEnvName(s),r=$t(n,o),a=ke(e),c=et(e),d=[`1. Revoke / rotate credential immediately with provider: ${t.provider}`,`2. Migrate secret value to local .env file (${o})`,`3. Replace hardcoded literal in ${n} with ${r}`,"4. Verify .env is listed in .gitignore so it is never committed","5. If committed previously, purge from Git history using git-filter-repo or BFG","6. Rescan file and commit to verify exposure is eliminated"],u=`${o}="${c}"`,p=`${o}=your_${o.toLowerCase()}_here`,l=`# WARNING: Use BFG Repo Cleaner to purge secrets from history (safer than filter-repo --invert-paths):
#   java -jar bfg.jar --replace-text secrets.txt <repo-dir>
# Where secrets.txt lists the exact literal to redact (one per line).
# Then force-push: git push --force --all && git push --force --tags
# Alternatively with git-filter-repo (rewrites content, not paths):
#   git filter-repo --replace-text secrets.txt`,f=`--- a/${n}
+++ b/${n}
@@ -${i},1 +${i},1 @@
- ... "${a}" ...
+ ... ${r} ...`;return{steps:d,envVarName:o,replacementCode:r,envFileSnippet:u,envExampleSnippet:p,gitHistoryPurgeCommand:l,diffPreview:f}}function kn(t,e,n){let i=t.split(/\r?\n/),s=new Map;for(let o of i){let r=o.trim();if(!r||r.startsWith("#"))continue;let a=r.indexOf("=");if(a!==-1){let c=r.substring(0,a).trim(),d=r.substring(a+1).trim();(d.startsWith('"')&&d.endsWith('"')||d.startsWith("'")&&d.endsWith("'"))&&(d=d.substring(1,d.length-1)),s.set(c,d)}}if(s.has(e)){let o=s.get(e);if(o===et(n)||o===n)return{varName:e,isReused:!0};let r=2;for(;s.has(`${e}_${r}`);){if(s.get(`${e}_${r}`)===n)return{varName:`${e}_${r}`,isReused:!0};r++}return{varName:`${e}_${r}`,isReused:!1}}return{varName:e,isReused:!1}}function En(t){let e=re.join(t,".gitignore");if(V.existsSync(e)){let n=V.readFileSync(e,"utf8");if(!n.split(/\r?\n/).some(o=>/^\s*\.env(?:\s|$)/.test(o))){let o=n.endsWith(`
`)||n.length===0?"":`
`;V.appendFileSync(e,`${o}# Credentials
.env
.env.*.local
`,"utf8")}}else V.writeFileSync(e,`# Credentials
.env
.env.*.local
`,"utf8");try{let{execFileSync:n}=require("child_process");try{n("git",["rev-parse","--is-inside-work-tree"],{cwd:t,stdio:"ignore"})}catch{return}try{throw n("git",["ls-files","--error-unmatch",".env"],{cwd:t,stdio:"ignore"}),new Error('.env is already tracked in Git index. Run "git rm --cached .env" to untrack it before storing secrets.')}catch(i){if(i.message&&i.message.includes("already tracked in Git index"))throw i}try{n("git",["check-ignore","-q",".env"],{cwd:t,stdio:"ignore"})}catch{throw new Error(".env is not ignored by Git according to git check-ignore.")}}catch(n){if(n.message&&(n.message.includes("already tracked")||n.message.includes("not ignored by Git")))throw n}}function An(t,e=V,n=process.platform,i=bn){if(n==="win32"){e.accessSync(t,V.constants.R_OK|V.constants.W_OK);let s=process.env.USERNAME||process.env.USER;if(!s)try{s=Nt.userInfo().username}catch{}if(!s)throw new Error("Failed to enforce Windows ACLs: neither USERNAME nor USER environment variable is set");try{i.execFileSync("icacls",[t,"/inheritance:r","/grant:r",`${s}:F`],{stdio:"pipe",windowsHide:!0});let r=i.execFileSync("icacls",[t],{encoding:"utf8",stdio:"pipe",windowsHide:!0}).toString().split(/\r?\n/).filter(p=>p.trim().length>0),a=[],c=s.toLowerCase();for(let p of r){if(/successfully processed|failed processing|processed file/i.test(p))continue;let l=p.match(/(?:^|[^\\]\s+|^.+?\s+)([A-Za-z0-9_\\\-\.\$@ ]+?):(\([^\)]+\)+)/);if(l){let f=l[1].trim(),m=f.split("\\").pop()?.toLowerCase()||"",h=f.toLowerCase();!(m===c||h.endsWith(`\\${c}`)||h===c)&&!(h==="nt authority\\system"||m==="system")&&a.push(f)}}for(let p of a)try{i.execFileSync("icacls",[t,"/remove",p],{stdio:"pipe",windowsHide:!0})}catch(l){throw new Error(`Failed to remove unsafe explicit ACL for account '${p}': ${l?.message||l}`)}let d=i.execFileSync("icacls",[t],{encoding:"utf8",stdio:"pipe",windowsHide:!0}).toString(),u=[];for(let p of d.split(/\r?\n/).filter(Boolean)){if(/successfully processed|failed processing|processed file/i.test(p))continue;let l=p.match(/(?:^|[^\\]\s+|^.+?\s+)([A-Za-z0-9_\\\-\.\$@ ]+?):(\([^\)]+\)+)/);if(l){let f=l[1].trim(),m=f.split("\\").pop()?.toLowerCase()||"",h=f.toLowerCase();!(m===c||h.endsWith(`\\${c}`)||h===c)&&!(h==="nt authority\\system"||m==="system")&&u.push(f)}}if(u.length>0)throw new Error(`Security error: Windows ACL enforcement failed on '${t}'. Unsafe explicit permissions remain for: ${u.join(", ")}`);return{enforced:!0,details:`ACL hardened exclusively for ${s}`}}catch(o){let r=o?.message||String(o);if(/does not support ACL|not supported|Incorrect function|No security ID|0x80070001|The volume does not support/i.test(r))return{enforced:!1,isUnsupportedFs:!0,details:`Volume does not support ACLs (FAT32/exFAT): ${r}`};throw new Error(`Failed to enforce Windows ACL protection on '${t}': ${r}`)}}else{try{e.chmodSync(t,384)}catch(r){throw new Error(`Failed to chmod .env to 0600: ${r?.message||r}`)}let o=e.statSync(t).mode&511;if(o&63)throw new Error(`Permission enforcement failed: .env file mode is 0o${o.toString(8)}, expected 0o600`);return{enforced:!0,details:"POSIX mode set to 0600"}}}function Dt(t,e,n=V){let i=t.fullPath,s=null,o=null,r=null,a=null,c=!1,d=!1,u=!1,p=re.join(e,".env"),l=re.join(e,".gitignore");try{if(!n.existsSync(i))return{success:!1,message:`Target file not found: ${i}`,envPath:"",modifiedFile:i};s=n.readFileSync(i,"utf8");let f=t.sourceExpression||t.rawSecret;if(!s.includes(f)&&!s.includes(t.rawSecret))return{success:!1,message:"Secret no longer found in target file (may have already been modified).",envPath:"",modifiedFile:i};let m="";if(n.existsSync(p))o=n.readFileSync(p,"utf8"),m=o;else{c=!0;try{n.writeFileSync(p,"",{mode:384,encoding:"utf8"})}catch{}}n.existsSync(l)?r=n.readFileSync(l,"utf8"):d=!0;let h=t.remediation?.envVarName||"API_KEY",{varName:k,isReused:E}=kn(m,h,t.rawSecret),v=$t(i,k),C=et(t.rawSecret),I=`${k}="${C}"
`;if(En(e),!E){let b=m.endsWith(`
`)||m.length===0?"":`
`;n.appendFileSync(p,`${b}${I}`,"utf8")}An(p,n);let O=re.join(e,".env.example"),g=`${k}=your_${k.toLowerCase()}_here
`,A=n.existsSync(O);if(A?a=n.readFileSync(O,"utf8"):u=!0,!A||!n.readFileSync(O,"utf8").includes(k)){let b=A?n.readFileSync(O,"utf8"):"",L=b.endsWith(`
`)||b.length===0?"":`
`;n.appendFileSync(O,`${L}${g}`,"utf8")}let y=s,M=t.sourceExpression||t.rawSecret,_=`"${M}"`,w=`'${M}'`,R=`\`${M}\``;return y.includes(_)?y=y.replace(new RegExp(Ee(_),"g"),v):y.includes(w)?y=y.replace(new RegExp(Ee(w),"g"),v):y.includes(R)?y=y.replace(new RegExp(Ee(R),"g"),v):y.includes(M)?y=y.replace(new RegExp(Ee(M),"g"),v):y=y.replace(new RegExp(Ee(t.rawSecret),"g"),v),n.writeFileSync(i,y,"utf8"),{success:!0,message:`Successfully migrated ${t.type} to .env (${k}) and replaced in ${t.file}.`,envPath:p,modifiedFile:i}}catch(f){let m=[],h=(v,C)=>{let I=`${v}.sld-tmp-${Date.now()}`;n.writeFileSync(I,C,"utf8"),n.renameSync(I,v)};if(s!==null)try{h(i,s),n.readFileSync(i,"utf8")!==s&&m.push(`source file restored with mismatched content (${i})`)}catch(v){m.push(`source file restore failed (${i}): ${v.message}`)}if(c&&n.existsSync(p))try{n.unlinkSync(p),n.existsSync(p)&&m.push(".env delete did not take effect")}catch(v){m.push(`.env delete failed: ${v.message}`)}else if(o!==null&&n.existsSync(p))try{h(p,o)}catch(v){m.push(`.env restore failed: ${v.message}`)}if(d&&n.existsSync(l))try{n.unlinkSync(l),n.existsSync(l)&&m.push(".gitignore delete did not take effect")}catch(v){m.push(`.gitignore delete failed: ${v.message}`)}else if(r!==null&&n.existsSync(l))try{h(l,r)}catch(v){m.push(`.gitignore restore failed: ${v.message}`)}let k=re.join(e,".env.example");if(u&&n.existsSync(k))try{n.unlinkSync(k),n.existsSync(k)&&m.push(".env.example delete did not take effect")}catch(v){m.push(`.env.example delete failed: ${v.message}`)}else if(a!==null&&n.existsSync(k))try{h(k,a)}catch(v){m.push(`.env.example restore failed: ${v.message}`)}let E=m.length===0?"Rollback completed successfully.":`ROLLBACK INCOMPLETE \u2014 manual inspection required: ${m.join("; ")}`;return{success:!1,message:`Remediation failed: ${f.message}. ${E}`,envPath:"",modifiedFile:t.fullPath}}}function Ee(t){return t.replace(/[.*+?^${}()|[\]\\]/g,"\\$&")}var Fe=D(require("zlib"));function Oe(t,e){let n="",i=t.length-t.length%4;for(let s=0;s<i;s+=4){let o=e?t.readUInt32LE(s):t.readUInt32BE(s);o!==0&&o<=1114111&&!(o>=55296&&o<=57343)&&(n+=String.fromCodePoint(o))}return n}function le(t){if(t.length===0)return"";if(t.length>=2&&t[0]===31&&t[1]===139)try{let o=Fe.gunzipSync(t,{maxOutputLength:67108864,finishFlush:Fe.constants.Z_SYNC_FLUSH}),r=le(o);if(r!==null)return r}catch{}if(t.length>=4){if(t[0]===255&&t[1]===254&&t[2]===0&&t[3]===0)return Oe(t.subarray(4),!0);if(t[0]===0&&t[1]===0&&t[2]===254&&t[3]===255)return Oe(t.subarray(4),!1)}if(t.length>=2&&t[0]===255&&t[1]===254)return t.subarray(2).toString("utf16le");if(t.length>=2&&t[0]===254&&t[1]===255){let o=Buffer.from(t.subarray(2));return o.swap16(),o.toString("utf16le")}if(t.length>=8){let o=Math.min(t.length-t.length%4,256),r=0,a=0;for(let d=0;d<o;d+=4)t[d+1]===0&&t[d+2]===0&&t[d+3]===0&&t[d]!==0&&r++,t[d]===0&&t[d+1]===0&&t[d+2]===0&&t[d+3]!==0&&a++;let c=o/4;if(r>c*.3)return Oe(t,!0);if(a>c*.3)return Oe(t,!1)}if(t.length>=4){let o=0,r=0,a=Math.min(t.length,512);for(let c=0;c<a;c++)t[c]===0&&(c%2===1?o++:r++);if(o>=2&&o>r*2&&o/(a/2)>.25)return t.toString("utf16le");if(r>=2&&r>o*2&&r/(a/2)>.25){let c=Buffer.from(t);return c.swap16(),c.toString("utf16le")}}let e=Math.min(t.length,8192),n=0;for(let o=0;o<e;o++){let r=t[o];(r>=0&&r<=8||r===11||r===12||r>=14&&r<=31)&&n++}if(n<=e*.2)return t.toString("utf8").replace(/\0/g," ");let s=t.toString("latin1").match(/[\x20-\x7E\t]{8,}/g);return s&&s.length>0?s.join(`
`):null}function Mt(t){return Wt.createHash("sha256").update(t.replace(/\\/g,"/")).digest("hex").slice(0,8)}function Bt(t){let e=t.groups?.secret;if(e===void 0){for(let s=1;s<t.length;s++)if(t[s]!==void 0){e=t[s];break}}let n=e!==void 0?e:t[0],i=e!==void 0?t[0].indexOf(e):0;return{secret:n,offset:i>=0?i:0}}function xn(t,e=4e3){let n=t.split(/\r?\n/),i=!1;for(let a=0;a<n.length;a++)if(n[a].length>e){i=!0;break}if(!i){let a=n.map((d,u)=>u+1),c=new Array(n.length).fill(0);return{text:t,origLine:a,colOffset:c}}let s=[],o=[],r=[];for(let a=0;a<n.length;a++){let c=n[a],d=a+1;if(c.length<=e)s.push(c),o.push(d),r.push(0);else for(let p=0;p<c.length&&(s.push(c.substring(p,p+e)),o.push(d),r.push(p),!(p+e>=c.length));p+=e-512);}return{text:s.join(`
`),origLine:o,colOffset:r}}function Kt(t,e){return/(?:\/\/|#|\/\*|--)\s*(?:sld-ignore|secret-leak-ignore)/i.test(t)?!0:/^\s*(?:\/\/|#|\/\*|--)\s*(?:sld-ignore|secret-leak-ignore)(?:\s*\*\/)?\s*$/i.test(e)}function pe(t,e,n={}){let i=typeof n=="string"?{workspaceRoot:n}:n,{text:s,origLine:o,colOffset:r}=xn(t),a=i.rules||gt,c=i.workspaceRoot,d=ft(e,c),u=t.split(/\r?\n/),p=[],l=!e||/\.[jt]sx?$|\.m[jt]s$|\.c[jt]s$/i.test(e),f=i.cachedSourceFile||null,m=!!i.cachedSourceFile;function h(){return m||(f=l?Ze(t,e):null,m=!0,f&&i.onSourceFileParsed&&i.onSourceFileParsed(f)),f}let k=null;function E(){if(!k){k=[0];for(let b=0;b<s.length;b++)s.charCodeAt(b)===10&&k.push(b+1)}return k}function v(b){let L=E(),$=0,K=L.length-1;for(;$<=K;){let U=$+K>>1;if(L[U]<=b){if(U===L.length-1||L[U+1]>b){let J=U,se=b-L[U]+1,ne=o[J]!==void 0?o[J]:J+1,me=(r[J]||0)+se;return{line:ne,column:me}}$=U+1}else K=U-1}let B=o[0]!==void 0?o[0]:1,G=(r[0]||0)+b+1;return{line:B,column:G}}function C(b){let L=b-1;if(u.length<=1e3)return{lines:u,relativeTargetIdx:L};let $=Math.max(0,L-30),K=Math.min(u.length-1,L+30);return{lines:u.slice($,K+1),relativeTargetIdx:L-$}}for(let b of a){b.pattern.lastIndex=0;let L;for(;(L=b.pattern.exec(s))!==null;){let{secret:$,offset:K}=Bt(L),B=L.index+K,{line:G,column:U}=v(B),J=u[G-1]||"",se=G>1?u[G-2]:"";if(!i?.disallowInlineIgnore&&Kt(J,se))continue;let ne=C(G),me=Ge(ne.lines,ne.relativeTargetIdx),X=qe(ne.lines,ne.relativeTargetIdx,e,h(),G-1),Y=Je(b,$,d,me,e,X);if(Y.isSuppressed)continue;let ie;if(b.minEntropy!==void 0&&(b.id==="generic-api-key"&&i.minEntropyThreshold!==void 0?ie=i.minEntropyThreshold:ie=b.minEntropy),ie!==void 0&&Y.evidence.shannonEntropy<ie)continue;let ce=e;if(c){let ye=he.relative(c,e);!ye.startsWith("..")&&!he.isAbsolute(ye)&&(ce=ye)}let Se=Xe(b,Y.confidence,d),Ce=tt(b,$,ce,G,me.inferredVariable),Ie=Mt(ce),_e=Qe($,void 0,c),ze=`sec_${_e}_${Ie}`,de=ke($),en={id:ze,fingerprint:_e,type:b.name,provider:b.provider,file:ce,fullPath:e,line:G,column:U,length:$.length,rawSecret:$,redactedSecret:de,confidence:Y.confidence,risk:Se.tier,riskAssessment:Se,evidence:Y.evidence,remediation:Ce,status:"ACTIVE",detectedAt:new Date().toISOString(),signals:Y.evidence.items.map(ye=>ye.description),exampleFix:Ce.replacementCode,entropy:Y.evidence.shannonEntropy};p.push(en)}}let I=[],O=/["']([^"'\r\n]{2,80})["']\s*\+\s*["']([^"'\r\n]{8,120})["']/g,g;for(;(g=O.exec(s))!==null;)I.push({combined:g[1]+g[2],matchOffset:g.index,matchLength:g[0].length,description:"Resolved split string concatenation",rawSource:g[0]});let A=/\[([^\]\r\n]{4,300})\]\s*\.\s*join\s*\(\s*["']\s*["']\s*\)/g,y;for(;(y=A.exec(s))!==null;){let b=/["']([^"'\r\n]*)["']/g,L=[],$;for(;($=b.exec(y[1]))!==null;)L.push($[1]);L.length>=2&&I.push({combined:L.join(""),matchOffset:y.index,matchLength:y[0].length,description:"Resolved split array join expression",rawSource:y[0]})}let M=/`([^`\r\n]{2,80})\$\{\s*["']([^"'\r\n]{8,120})["']\s*\}([^`\r\n]*?)`/g,_;for(;(_=M.exec(s))!==null;)I.push({combined:_[1]+_[2]+(_[3]||""),matchOffset:_.index,matchLength:_[0].length,description:"Resolved template literal interpolation",rawSource:_[0]});let w=/(?:(?:Buffer\.from|atob|b64decode|b64_decode|base64_decode|DecodeString)\s*\(\s*(?:b)?["']([A-Za-z0-9+/=_-]{20,300})["']|["']([A-Za-z0-9+/_-]{20,}={0,2})["']|(?:=|\:)\s*([A-Za-z0-9+/_-]{20,}={0,2})|(?:^|[\r\n\s])([A-Za-z0-9+/_-]{24,}={0,2})(?:[\r\n\s]|$))/g,R;for(;(R=w.exec(s))!==null;){let b=R[1]||R[2]||R[3]||R[4];if(b)try{let L=b.replace(/-/g,"+").replace(/_/g,"/"),$=(4-L.length%4)%4,K=L+"=".repeat($),B=Buffer.from(K,"base64").toString("utf8");B.length>=10&&/^[\x20-\x7E\r\n\t]+$/.test(B)&&I.push({combined:B,matchOffset:R.index,matchLength:R[0].length,description:"Resolved base64-encoded credential payload",rawSource:R[0]})}catch{}}for(let b of I)for(let L of a){L.pattern.lastIndex=0;let $;for(;($=L.pattern.exec(b.combined))!==null;){let{secret:K}=Bt($),{line:B,column:G}=v(b.matchOffset),U=u[B-1]||"",J=B>1?u[B-2]:"";if(!i?.disallowInlineIgnore&&Kt(U,J))continue;let se=C(B),ne=Ge(se.lines,se.relativeTargetIdx),me=qe(se.lines,se.relativeTargetIdx,e,h(),B-1),X=Je(L,K,d,ne,e,me);if(X.isSuppressed)continue;let Y;if(L.minEntropy!==void 0&&(L.id==="generic-api-key"&&i.minEntropyThreshold!==void 0?Y=i.minEntropyThreshold:Y=L.minEntropy),Y!==void 0&&X.evidence.shannonEntropy<Y)continue;let ie=e;if(c){let de=he.relative(c,e);!de.startsWith("..")&&!he.isAbsolute(de)&&(ie=de)}let ce=Xe(L,X.confidence,d),Se=tt(L,K,ie,B,ne.inferredVariable);X.evidence.items.unshift({signal:"ADVERSARIAL_DEOBFUSCATION_RESOLVED",description:b.description,confidenceImpact:10});let Ce=Mt(ie),Ie=Qe(K,void 0,c),_e=`sec_${Ie}_${Ce}`,ze=ke(K);p.push({id:_e,fingerprint:Ie,type:L.name,provider:L.provider,file:ie,fullPath:e,line:B,column:G,length:b.matchLength,rawSecret:K,sourceExpression:b.rawSource,redactedSecret:ze,confidence:Math.min(100,X.confidence+5),risk:ce.tier,riskAssessment:ce,evidence:X.evidence,remediation:Se,status:"ACTIVE",detectedAt:new Date().toISOString(),signals:X.evidence.items.map(de=>de.description),exampleFix:Se.replacementCode,entropy:X.evidence.shannonEntropy})}}return wn(p)}function wn(t){let e=[];for(let n of t){let i=e.findIndex(s=>s.file===n.file&&s.line===n.line&&(s.rawSecret.includes(n.rawSecret)||n.rawSecret.includes(s.rawSecret)));if(i===-1)e.push(n);else{let s=e[i];(s.provider==="Generic Credential"&&n.provider!=="Generic Credential"||n.confidence>s.confidence)&&(e[i]=n)}}return e}var Pe=class{diagnosticCollection;currentFindings=new Map;ignoredFindings=new Set;documentAstCache=new Map;onFindingsChangedEmitter=new N.EventEmitter;onFindingsChanged=this.onFindingsChangedEmitter.event;minEntropy;constructor(){this.diagnosticCollection=N.languages.createDiagnosticCollection("secret-leak-detector")}setMinEntropy(e){this.minEntropy=e}getDiagnosticCollection(){return this.diagnosticCollection}getAllFindings(){let e=[];for(let n of this.currentFindings.values())e.push(...n);return e}clear(){this.diagnosticCollection.clear(),this.currentFindings.clear(),this.documentAstCache.clear(),this.onFindingsChangedEmitter.fire([])}ignoreFinding(e){this.ignoredFindings.add(e);for(let[n,i]of this.currentFindings.entries()){let s=i.filter(o=>o.id!==e);if(s.length!==i.length){this.currentFindings.set(n,s);let o=N.Uri.file(n),r=this.diagnosticCollection.get(o);if(r){let a=r.filter(c=>(typeof c.code=="object"?c.code?.value:c.code)!==e);this.diagnosticCollection.set(o,a)}}}this.onFindingsChangedEmitter.fire(this.getAllFindings())}setIgnoredFindings(e){this.ignoredFindings=new Set(e)}getIgnoredFindings(){return Array.from(this.ignoredFindings)}scanDocument(e){let n=e.uri.scheme==="file",i=e.uri.scheme==="untitled";if(!n&&!i)return[];let s=e.getText();if(s.length>5*1024*1024)return[];let o=N.workspace.getWorkspaceFolder(e.uri),r=o?o.uri.fsPath:void 0,a=n?e.uri.fsPath:e.fileName||"untitled.ts",c=null,d=this.documentAstCache.get(e.uri.toString());d&&d.version===e.version&&(c=d.sourceFile);let u={workspaceRoot:r,minEntropyThreshold:this.minEntropy,cachedSourceFile:c,onSourceFileParsed:h=>{this.documentAstCache.set(e.uri.toString(),{version:e.version,sourceFile:h})}},l=pe(s,a,u).filter(h=>!this.ignoredFindings.has(h.id)),f=e.uri.fsPath||e.uri.toString();this.currentFindings.set(f,l);let m=[];for(let h of l){let k=Math.max(0,h.line-1),E=Math.max(0,h.column-1),v=new N.Position(k,E),C=e.offsetAt(v),I=e.positionAt(C+h.length),O=new N.Range(v,I),g=N.DiagnosticSeverity.Warning;h.risk==="CRITICAL"||h.risk==="HIGH"?g=N.DiagnosticSeverity.Error:h.risk==="LOW"&&(g=N.DiagnosticSeverity.Information);let A=typeof h.remediation=="string"?h.remediation:h.remediation?.steps?.[0]||"Migrate to .env",y=new N.Diagnostic(O,`[Secret Leak Detector] ${h.type} detected! Confidence: ${h.confidence}%. ${A}`,g);y.code={value:h.id,target:N.Uri.parse("https://github.com/MokuLakshithReddy/Secret_Leak_Detector")},y.source="Secret Leak Detector",m.push(y)}return this.diagnosticCollection.set(e.uri,m),this.onFindingsChangedEmitter.fire(this.getAllFindings()),l}toDiagnostic(e){let n=Math.max(0,e.line-1),i=Math.max(0,e.column-1),s=new N.Position(n,i),o,r=e.rawSecret||(e.evidence?.surroundingCode?.targetLine?e.redactedSecret:"");if(r&&r.includes(`
`)){let p=r.split(/\r?\n/),l=n+p.length-1,f=p.length>1?p[p.length-1].length:i+p[0].length;o=new N.Position(l,f)}else o=new N.Position(n,i+e.length);let a=new N.Range(s,o),c=N.DiagnosticSeverity.Warning;e.risk==="CRITICAL"||e.risk==="HIGH"?c=N.DiagnosticSeverity.Error:e.risk==="LOW"&&(c=N.DiagnosticSeverity.Information);let d=typeof e.remediation=="string"?e.remediation:e.remediation?.steps?.[0]||"Migrate to .env",u=new N.Diagnostic(a,`[Secret Leak Detector] ${e.type} detected! Confidence: ${e.confidence}%. ${d}`,c);return u.code={value:e.id,target:N.Uri.parse("https://github.com/MokuLakshithReddy/Secret_Leak_Detector")},u.source="Secret Leak Detector",u}setBatchFindings(e){this.diagnosticCollection.clear(),this.currentFindings.clear();for(let[n,i]of e.entries()){let s=i.filter(o=>!this.ignoredFindings.has(o.id));if(this.currentFindings.set(n,s),s.length>0){let o=N.Uri.file(n),r=s.map(a=>this.toDiagnostic(a));this.diagnosticCollection.set(o,r)}}this.onFindingsChangedEmitter.fire(this.getAllFindings())}mergeBatchFindings(e){for(let[n,i]of e.entries()){let s=N.Uri.file(n),o=i.filter(r=>!this.ignoredFindings.has(r.id));if(o.length>0){this.currentFindings.set(n,o);let r=o.map(a=>this.toDiagnostic(a));this.diagnosticCollection.set(s,r)}else this.currentFindings.delete(n),this.diagnosticCollection.delete(s)}this.onFindingsChangedEmitter.fire(this.getAllFindings())}renameDocument(e,n){let i=this.currentFindings.get(e.fsPath);if(this.removeDocument(e),i&&i.length>0){let s=i.map(r=>({...r,fullPath:n.fsPath,file:n.fsPath}));this.currentFindings.set(n.fsPath,s);let o=s.map(r=>this.toDiagnostic(r));this.diagnosticCollection.set(n,o),this.onFindingsChangedEmitter.fire(this.getAllFindings())}}removeDocument(e){this.diagnosticCollection.delete(e),e.fsPath&&this.currentFindings.delete(e.fsPath),this.currentFindings.delete(e.toString()),this.documentAstCache.delete(e.toString()),this.onFindingsChangedEmitter.fire(this.getAllFindings())}dispose(){this.diagnosticCollection.dispose(),this.documentAstCache.clear(),this.onFindingsChangedEmitter.dispose()}};var z=D(require("vscode"));var ve=class{static providedCodeActionKinds=[z.CodeActionKind.QuickFix];diagnosticProvider;constructor(e){this.diagnosticProvider=e}provideCodeActions(e,n,i){let s=[],o=i.diagnostics.filter(a=>a.source==="Secret Leak Detector");if(o.length===0)return s;let r=this.diagnosticProvider.getAllFindings();for(let a of o){let c=typeof a.code=="object"?a.code?.value:a.code,d=r.find(m=>m.id===c);if(!d)continue;let u=e.getText(a.range);if(u!==d.rawSecret&&u!==d.sourceExpression)continue;let p=!!z.workspace.getWorkspaceFolder(e.uri),l=!e.isUntitled&&e.uri.scheme==="file";if(p&&l){let m=this.createMoveToEnvAction(e,a.range,d);s.push(m)}let f=new z.CodeAction("Ignore this finding (False Positive)",z.CodeActionKind.QuickFix);f.command={command:"secret-leak-detector.ignoreFinding",title:"Ignore Finding",arguments:[d.id]},s.push(f)}return s}createMoveToEnvAction(e,n,i){let s=new z.CodeAction(`\u{1F6E1}\uFE0F Move ${i.type} to .env and replace with environment variable`,z.CodeActionKind.QuickFix);return s.isPreferred=!0,s.command={command:"secret-leak-detector.remediateFinding",title:"Move to .env",arguments:[e.uri,n,i]},s}static async executeRemediation(e,n,i){let s=z.workspace.getWorkspaceFolder(e);if(!s){z.window.showErrorMessage("No workspace folder found to save .env file.");return}let o=s.uri.fsPath,a=(await z.workspace.openTextDocument(e)).getText(n),c=i.sourceExpression||i.rawSecret;if(a!==c&&a!==i.rawSecret){z.window.showErrorMessage("The secret at the target location has changed or was already removed.");return}let d=Dt(i,o);if(!d.success){z.window.showErrorMessage(`Remediation aborted: ${d.message}`);return}z.window.showInformationMessage(`\u{1F6E1}\uFE0F ${d.message}`)}};var T=D(require("vscode")),Ne=class{_onDidChangeTreeData=new T.EventEmitter;onDidChangeTreeData=this._onDidChangeTreeData.event;findings=[];dispose(){this._onDidChangeTreeData.dispose()}updateFindings(e){this.findings=e,this._onDidChangeTreeData.fire()}getTreeItem(e){return e}getChildren(e){if(!e){if(this.findings.length===0){let s=new ee("No Leaks Detected (Safe)",T.TreeItemCollapsibleState.None);return s.iconPath=new T.ThemeIcon("shield-check",new T.ThemeColor("testing.iconPassed")),s.description="Workspace is clean",Promise.resolve([s])}let n=["CRITICAL","HIGH","MEDIUM","LOW"],i=[];for(let s of n){let o=this.findings.filter(r=>r.risk===s).length;if(o>0){let r=new ee(`${s} Risk (${o})`,T.TreeItemCollapsibleState.Expanded,s);s==="CRITICAL"?r.iconPath=new T.ThemeIcon("error",new T.ThemeColor("errorForeground")):s==="HIGH"?r.iconPath=new T.ThemeIcon("warning",new T.ThemeColor("editorWarning.foreground")):s==="MEDIUM"?r.iconPath=new T.ThemeIcon("info",new T.ThemeColor("editorInfo.foreground")):r.iconPath=new T.ThemeIcon("pass",new T.ThemeColor("testing.iconPassed")),i.push(r)}}return Promise.resolve(i)}if(e.contextValue){let n=e.contextValue,i=this.findings.filter(r=>r.risk===n),s=T.workspace.getConfiguration("secretLeakDetector").get("redactSecrets",!0),o=i.map(r=>{let a=new ee(`${r.type}`,T.TreeItemCollapsibleState.None),c=s?r.redactedSecret:r.rawSecret,d=typeof r.remediation?.replacementCode=="string"?r.remediation.replacementCode:typeof r.remediation?.envVarName=="string"?`process.env.${r.remediation.envVarName}`:"Migrate to .env";return a.description=`${r.file}:${r.line}`,a.tooltip=new T.MarkdownString(`**${r.type}** (${r.provider})

- **Risk:** ${r.risk}
- **Confidence:** ${r.confidence}%
- **Entropy:** ${r.entropy} bits/char
- **Secret:** \`${c}\`

*Suggested Fix: ${d}*`),a.iconPath=new T.ThemeIcon("key"),a.command={command:"vscode.open",title:"Jump to Secret",arguments:[T.Uri.file(r.fullPath),{selection:new T.Range(r.line-1,r.column-1,r.line-1,r.column-1+r.length)}]},a});return Promise.resolve(o)}return Promise.resolve([])}},$e=class{_onDidChangeTreeData=new T.EventEmitter;onDidChangeTreeData=this._onDidChangeTreeData.event;findingsCount=0;isGit=!0;dispose(){this._onDidChangeTreeData.dispose()}update(e,n){this.findingsCount=e,this.isGit=n,this._onDidChangeTreeData.fire()}getTreeItem(e){return e}getChildren(){let e=[],n=new ee(this.findingsCount===0?"Status: Protected":`Status: ${this.findingsCount} Leaks Active`,T.TreeItemCollapsibleState.None);n.iconPath=new T.ThemeIcon(this.findingsCount===0?"check":"alert",this.findingsCount===0?new T.ThemeColor("testing.iconPassed"):new T.ThemeColor("errorForeground")),e.push(n);let i=new ee("Run Full Workspace Scan",T.TreeItemCollapsibleState.None);i.iconPath=new T.ThemeIcon("search"),i.command={command:"secret-leak-detector.scanWorkspace",title:"Scan Workspace"},e.push(i);let s=new ee("Check Git Staged Changes",T.TreeItemCollapsibleState.None);s.iconPath=new T.ThemeIcon("git-commit"),s.command={command:"secret-leak-detector.scanStaged",title:"Scan Staged Changes"},e.push(s);let o=new ee("Open Interactive Dashboard",T.TreeItemCollapsibleState.None);o.iconPath=new T.ThemeIcon("dashboard"),o.command={command:"secret-leak-detector.openDashboard",title:"Open Dashboard"},e.push(o);let r=new ee("Install Pre-Commit Hook",T.TreeItemCollapsibleState.None);return r.iconPath=new T.ThemeIcon("terminal"),r.command={command:"secret-leak-detector.installGitHook",title:"Install Hook"},e.push(r),Promise.resolve(e)}},ee=class extends T.TreeItem{constructor(e,n,i){super(e,n),this.contextValue=i}};var H=D(require("vscode")),Ht=D(require("crypto")),it=D(require("fs")),Ae=D(require("path"));function nt(t){let e=typeof t.remediation=="string"?t.remediation:t.remediation?.steps?.join("; ")||"Rotate and move to .env",n=t.exampleFix||t.remediation?.replacementCode||"";return{id:t.id,type:t.type,provider:t.provider,file:t.file,fullPath:t.fullPath,line:t.line,column:t.column,redactedSecret:t.redactedSecret,confidence:t.confidence,entropy:t.entropy??0,risk:t.risk,remediationText:e,exampleFix:n}}var ue=class t{static currentPanel;static viewType="secretLeakDetectorDashboard";_panel;_extensionUri;_disposables=[];_findings=[];static createOrShow(e,n){let i=H.window.activeTextEditor?H.window.activeTextEditor.viewColumn:void 0;if(t.currentPanel){t.currentPanel._panel.reveal(i),t.currentPanel.updateFindings(n);return}let s=H.window.createWebviewPanel(t.viewType,"\u{1F510} Secret Leak Detector Dashboard",i||H.ViewColumn.One,{enableScripts:!0,retainContextWhenHidden:!0,localResourceRoots:[e]});t.currentPanel=new t(s,e,n)}constructor(e,n,i){this._panel=e,this._extensionUri=n,this._findings=i,this._update(),this._panel.onDidDispose(()=>this.dispose(),null,this._disposables),this._panel.webview.onDidReceiveMessage(async s=>{switch(s.command){case"scanWorkspace":H.commands.executeCommand("secret-leak-detector.scanWorkspace");return;case"scanStaged":H.commands.executeCommand("secret-leak-detector.scanStaged");return;case"installHook":H.commands.executeCommand("secret-leak-detector.installGitHook");return;case"openFile":if(typeof s.file=="string"&&s.file.trim().length>0&&typeof s.line=="number"&&s.line>=1){let o=this._findings.find(a=>a.file===s.file||a.fullPath===s.file);if(!o)return;let r=o.fullPath||o.file;if(!Ae.isAbsolute(r)){let a=!1;for(let c of H.workspace.workspaceFolders||[]){let d=Ae.resolve(c.uri.fsPath,r);if(it.existsSync(d)){r=d,a=!0;break}}if(!a){let c=H.workspace.workspaceFolders?.[0]?.uri.fsPath||process.cwd();r=Ae.resolve(c,r)}}if(it.existsSync(r))try{let a=await H.workspace.openTextDocument(H.Uri.file(r));await H.window.showTextDocument(a,{selection:new H.Range(s.line-1,0,s.line-1,0)})}catch{}}return}},null,this._disposables)}updateFindings(e){this._findings=e;let n=this._findings.map(nt);this._panel.webview.postMessage({command:"updateData",findings:n})}dispose(){for(t.currentPanel=void 0,this._panel.dispose();this._disposables.length;){let e=this._disposables.pop();e&&e.dispose()}}_update(){this._panel.webview.html=this._getHtmlForWebview()}_getHtmlForWebview(){let e=Ht.randomBytes(16).toString("base64"),n=this._findings.map(nt),i=JSON.stringify(n).replace(/</g,"\\u003c");return`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-${e}';">
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
      <button id="btn-scan-staged">\u26A1 Scan Staged</button>
      <button id="btn-scan-workspace" class="primary">\u{1F50D} Full Workspace Scan</button>
      <button id="btn-install-hook">\u{1F6E1}\uFE0F Install Hook</button>
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
    <div class="tab active" data-tab="findings">Active Findings</div>
    <div class="tab" data-tab="blast">Blast Radius & Providers</div>
    <div class="tab" data-tab="workflow">Workflow Architecture</div>
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
BLOCK (Intercept git commit via pre-commit hook)
   \u2193
FIX (One-click Extraction to .env)
   \u2193
RESCAN (Validate Safe State)
   \u2193
ALLOW (Commit Proceeds)
    </pre>
  </div>

  <script id="sld-initial-data" type="application/json" nonce="${e}">${i}</script>
  <script nonce="${e}">
    const vscode = acquireVsCodeApi();
    let findings = [];

    try {
      const initialEl = document.getElementById('sld-initial-data');
      if (initialEl && initialEl.textContent) {
        findings = JSON.parse(initialEl.textContent);
      }
    } catch (e) {
      findings = [];
    }

    function openFile(file, line) {
      vscode.postMessage({ command: 'openFile', file, line });
    }

    function switchTab(tabId, targetEl) {
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      document.getElementById('tab-findings').style.display = tabId === 'findings' ? 'block' : 'none';
      document.getElementById('tab-blast').style.display = tabId === 'blast' ? 'block' : 'none';
      document.getElementById('tab-workflow').style.display = tabId === 'workflow' ? 'block' : 'none';
      if (targetEl) {
        targetEl.classList.add('active');
      }
    }

    function render() {
      const tbody = document.getElementById('findings-table-body');
      const emptyState = document.getElementById('empty-state');
      
      const totalCount = findings.length;
      const criticalCount = findings.filter(f => f.risk === 'CRITICAL').length;
      const highCount = findings.filter(f => f.risk === 'HIGH').length;

      document.getElementById('stat-total').textContent = String(totalCount);
      document.getElementById('stat-critical').textContent = String(criticalCount);
      document.getElementById('stat-high').textContent = String(highCount);
      const blockingCount = findings.filter(f => f.risk === 'CRITICAL' || f.risk === 'HIGH').length;
      const guardEl = document.getElementById('stat-guard');
      if (blockingCount > 0) {
        guardEl.textContent = 'BLOCKING (' + blockingCount + ')';
        guardEl.className = 'stat-value critical';
      } else if (totalCount > 0) {
        guardEl.textContent = 'WARNING (' + totalCount + ')';
        guardEl.className = 'stat-value';
      } else {
        guardEl.textContent = 'READY';
        guardEl.className = 'stat-value clean';
      }

      // Clear existing rows safely
      while (tbody.firstChild) {
        tbody.removeChild(tbody.firstChild);
      }

      if (findings.length === 0) {
        emptyState.style.display = 'block';
        renderBlast();
        return;
      }

      emptyState.style.display = 'none';

      for (const f of findings) {
        // Row 1: Finding details
        const tr1 = document.createElement('tr');

        // Col 1: Risk Tag
        const tdRisk = document.createElement('td');
        const tag = document.createElement('span');
        tag.className = 'tag tag-' + f.risk;
        tag.textContent = f.risk;
        tdRisk.appendChild(tag);
        tr1.appendChild(tdRisk);

        // Col 2: Type & Provider
        const tdType = document.createElement('td');
        const strongType = document.createElement('strong');
        strongType.textContent = f.type;
        const providerSpan = document.createElement('span');
        providerSpan.style.fontSize = '11px';
        providerSpan.style.color = 'var(--text-muted)';
        providerSpan.style.display = 'block';
        providerSpan.textContent = f.provider;
        tdType.appendChild(strongType);
        tdType.appendChild(providerSpan);
        tr1.appendChild(tdType);

        // Col 3: File & Line
        const tdFile = document.createElement('td');
        const fileLink = document.createElement('span');
        fileLink.className = 'file-link';
        fileLink.textContent = f.file + ':' + f.line;
        fileLink.addEventListener('click', () => openFile(f.fullPath, f.line));
        tdFile.appendChild(fileLink);
        tr1.appendChild(tdFile);

        // Col 4: Redacted Secret
        const tdSecret = document.createElement('td');
        const secretCode = document.createElement('span');
        secretCode.className = 'secret-code';
        secretCode.textContent = f.redactedSecret;
        tdSecret.appendChild(secretCode);
        tr1.appendChild(tdSecret);

        // Col 5: Confidence
        const tdConf = document.createElement('td');
        const strongConf = document.createElement('strong');
        strongConf.textContent = f.confidence + '%';
        tdConf.appendChild(strongConf);
        tr1.appendChild(tdConf);

        // Col 6: Entropy
        const tdEntropy = document.createElement('td');
        tdEntropy.textContent = (typeof f.entropy === 'number' ? f.entropy.toFixed(2) : f.entropy) + ' b/c';
        tr1.appendChild(tdEntropy);

        // Col 7: Action Button
        const tdAction = document.createElement('td');
        const btnView = document.createElement('button');
        btnView.textContent = 'View Line';
        btnView.addEventListener('click', () => openFile(f.fullPath, f.line));
        tdAction.appendChild(btnView);
        tr1.appendChild(tdAction);

        tbody.appendChild(tr1);

        // Row 2: Remediation Box
        const tr2 = document.createElement('tr');
        const tdRem = document.createElement('td');
        tdRem.colSpan = 7;
        tdRem.style.paddingTop = '0';
        tdRem.style.paddingBottom = '14px';
        tdRem.style.background = '#0e1420';

        const remBox = document.createElement('div');
        remBox.className = 'remediation-box';

        const remLabel = document.createElement('strong');
        remLabel.textContent = 'Remediation: ';
        const remText = document.createTextNode(f.remediationText);
        remBox.appendChild(remLabel);
        remBox.appendChild(remText);

        if (f.exampleFix) {
          const br = document.createElement('br');
          const codeFix = document.createElement('code');
          codeFix.textContent = f.exampleFix;
          codeFix.style.display = 'block';
          codeFix.style.marginTop = '4px';
          remBox.appendChild(br);
          remBox.appendChild(codeFix);
        }

        tdRem.appendChild(remBox);
        tr2.appendChild(tdRem);
        tbody.appendChild(tr2);
      }

      renderBlast();
    }

    function renderBlast() {
      const blastDiv = document.getElementById('blast-content');
      while (blastDiv.firstChild) {
        blastDiv.removeChild(blastDiv.firstChild);
      }

      const providers = {};
      findings.forEach(f => {
        providers[f.provider] = (providers[f.provider] || 0) + 1;
      });

      const grid = document.createElement('div');
      grid.style.display = 'grid';
      grid.style.gridTemplateColumns = '1fr 1fr';
      grid.style.gap = '16px';

      // Card 1
      const card1 = document.createElement('div');
      card1.style.background = '#080b11';
      card1.style.padding = '16px';
      card1.style.borderRadius = '6px';
      const h4_1 = document.createElement('h4');
      h4_1.textContent = 'Affected Providers';
      card1.appendChild(h4_1);

      const ul = document.createElement('ul');
      ul.style.marginTop = '8px';
      ul.style.paddingLeft = '20px';
      for (const [providerName, count] of Object.entries(providers)) {
        const li = document.createElement('li');
        const strongP = document.createElement('strong');
        strongP.textContent = providerName;
        li.appendChild(strongP);
        li.appendChild(document.createTextNode(': ' + count + ' occurrence(s)'));
        ul.appendChild(li);
      }
      card1.appendChild(ul);
      grid.appendChild(card1);

      // Card 2
      const card2 = document.createElement('div');
      card2.style.background = '#080b11';
      card2.style.padding = '16px';
      card2.style.borderRadius = '6px';
      const h4_2 = document.createElement('h4');
      h4_2.textContent = 'Total Exposure Surface';
      card2.appendChild(h4_2);

      const pSurface = document.createElement('p');
      pSurface.style.marginTop = '8px';
      const uniqueFiles = new Set(findings.map(f => f.file)).size;
      pSurface.textContent = findings.length + ' active credentials identified across ' + uniqueFiles + ' file(s).';
      card2.appendChild(pSurface);
      grid.appendChild(card2);

      blastDiv.appendChild(grid);
    }

    // Attach button listeners safely
    document.getElementById('btn-scan-staged')?.addEventListener('click', () => {
      vscode.postMessage({ command: 'scanStaged' });
    });
    document.getElementById('btn-scan-workspace')?.addEventListener('click', () => {
      vscode.postMessage({ command: 'scanWorkspace' });
    });
    document.getElementById('btn-install-hook')?.addEventListener('click', () => {
      vscode.postMessage({ command: 'installHook' });
    });

    document.querySelectorAll('.tab').forEach((tabEl) => {
      tabEl.addEventListener('click', () => {
        const targetTab = tabEl.getAttribute('data-tab');
        if (targetTab) switchTab(targetTab, tabEl);
      });
    });

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
</html>`}};var We=require("child_process"),Qt=require("util"),x=D(require("fs")),pt=D(require("os")),P=D(require("path"));var j=require("child_process"),zt=require("util"),ct=D(require("path"));var De=D(require("fs")),Me=D(require("path")),st=new Set([".exe",".dll",".so",".dylib",".iso",".dmg",".woff",".woff2",".ttf",".eot",".otf",".mp3",".mp4",".avi",".mov",".wmv",".flv",".mkv",".wav",".pyc",".pyo",".class",".o",".obj",".lib",".a"]),Ei=new Set([...st,".wasm",".pkl",".npy",".parquet",".onnx",".safetensors"]),Cn=["dist/**","build/**"],In=["**/node_modules/**","node_modules/**","**/.git/**",".git/**",".vscode-test/**","**/.vscode-test/**","package-lock.json","**/package-lock.json","pnpm-lock.yaml","**/pnpm-lock.yaml","yarn.lock","**/yarn.lock","bun.lockb","**/bun.lockb"],ot=[...In,...Cn];var ge=new Map;function _n(t){try{let{execFileSync:e}=require("child_process"),n=process.env.SLD_BASE_REF||process.env.GITHUB_BASE_REF||process.env.CI_MERGE_REQUEST_TARGET_BRANCH_NAME,i=process.env.GITHUB_EVENT_BEFORE||process.env.CI_COMMIT_BEFORE_SHA,s=[];n&&n!=="0000000000000000000000000000000000000000"&&s.push(`origin/${n}`,`refs/remotes/origin/${n}`,n),i&&i!=="0000000000000000000000000000000000000000"&&s.push(i),s.length===0&&s.push("HEAD~1");let o="";try{o=e("git",["rev-parse","HEAD"],{cwd:t,encoding:"utf8",stdio:["pipe","pipe","ignore"]}).trim()}catch{}for(let r of s)if(o)try{if(e("git",["rev-parse",r],{cwd:t,encoding:"utf8",stdio:["pipe","pipe","ignore"]}).trim()===o)continue;return r}catch{continue}else return r;return null}catch{return null}}function rt(t){let e=Me.resolve(t).replace(/\\/g,"/");if(ge.has(e))return ge.get(e);if(!!(process.env.CI||process.env.GITHUB_ACTIONS||process.env.GITLAB_CI))try{let{execFileSync:s}=require("child_process"),o=_n(t);if(o)try{let r=s("git",["show",`${o}:.sldignore`],{cwd:t,encoding:"utf8",stdio:["ignore","pipe","ignore"]});if(r){let a=r.split(/\r?\n/).map(c=>c.trim()).filter(c=>c.length>0&&!c.startsWith("#"));return ge.set(e,a),a}}catch{}return ge.set(e,[]),[]}catch{return ge.set(e,[]),[]}let i=Me.join(t,".sldignore");if(De.existsSync(i))try{let o=De.readFileSync(i,"utf8").split(/\r?\n/).map(r=>r.trim()).filter(r=>r.length>0&&!r.startsWith("#"));return ge.set(e,o),o}catch{}return ge.set(e,[]),[]}function Rn(t){let e=t.trim().replace(/\\/g,"/"),n=!1;e.endsWith("/")&&(n=!0,e=e.slice(0,-1));let i=e.startsWith("/");i&&(e=e.slice(1));let s="",o=0;for(;o<e.length;)e.slice(o,o+4)==="/**/"?(s+="(?:/|/.*/)",o+=4):e.slice(o,o+3)==="/**"?(s+="(/.*)?",o+=3):e.slice(o,o+3)==="**/"?(s+="(?:^|.*/)",o+=3):e.slice(o,o+2)==="**"?(s+=".*",o+=2):e[o]==="*"?(s+="[^/]*",o+=1):e[o]==="?"?(s+="[^/]",o+=1):[".","+","^","$","(",")","[","]","{","}","|"].includes(e[o])?(s+="\\"+e[o],o+=1):(s+=e[o],o+=1);return n?i||e.includes("/")?new RegExp("^"+s+"(/.*)?$"):new RegExp("(?:^|/)"+s+"(/.*)?$"):!e.includes("/")&&!i?new RegExp("(?:^|/)"+s+"$"):new RegExp("^"+s+"$")}function at(t,e){let n=t.replace(/\\/g,"/").replace(/^\/+/,""),i=e.trim().replace(/\\/g,"/");if(!i||i.startsWith("#"))return!1;if(n===i)return!0;let s=i.startsWith("/"),o=s?i.slice(1):i,r=o.endsWith("/")?o.slice(0,-1):o;if(!o.includes("*")){if(s||o.includes("/")){if(n===r||n.startsWith(r+"/"))return!0}else if(n===r||n.startsWith(r+"/")||n.includes("/"+r+"/"))return!0}try{return Rn(i).test(n)}catch{return!1}}var Be=(0,zt.promisify)(j.execFile),te=["--literal-pathspecs","-c","core.quotepath=false","-c","diff.noprefix=false","-c","diff.mnemonicPrefix=false","-c","color.diff=never"],Gt=50*1024*1024;function Tn(t){try{let e=(0,j.execFileSync)("git",["rev-parse","--show-toplevel"],{cwd:t,encoding:"utf8"}).trim();if(e)return ct.resolve(e)}catch{}return t}async function Ln(t){try{let{stdout:e}=await Be("git",["rev-parse","--show-toplevel"],{cwd:t,encoding:"utf8"}),n=e.trim();if(n)return ct.resolve(n)}catch{}return t}function Ut(t){let e=[],n=[],i=0;for(let o=0;o<t.length;o++)t[o]===0&&(n.push(t.toString("utf8",i,o)),i=o+1);let s=0;for(;s<n.length;){let o=n[s++];if(!o)break;let r=o[0];if(r==="R"||r==="C"){let a=n[s++],c=n[s++];c&&e.push({status:r,path:c.replace(/\\/g,"/"),oldPath:a?a.replace(/\\/g,"/"):void 0})}else{let a=n[s++];a&&e.push({status:r,path:a.replace(/\\/g,"/")})}}return e}function On(t,e){let n=new Map;if(e.length===0)return n;let i=e.map(o=>`:${o}
`).join(""),s=(0,j.spawnSync)("git",[...te,"cat-file","--batch-check"],{cwd:t,input:i,encoding:"utf8",maxBuffer:64*1024*1024});if(s.error)throw new Error(`git cat-file --batch-check failed: ${s.error.message}`);if(s.status!==0)throw new Error(`git cat-file --batch-check exited with code ${s.status}: ${s.stderr||""}`);if(s.stdout){let o=s.stdout.split(/\r?\n/);for(let r=0;r<e.length;r++){let a=o[r];if(!a)continue;let c=a.split(" ");c.length>=3&&c[1]==="blob"&&n.set(e[r],parseInt(c[2],10)||0)}}return n}function Fn(t,e){let n=new Map;if(e.length===0)return n;let i=e.map(c=>`:${c}
`).join(""),s=(0,j.spawnSync)("git",[...te,"cat-file","--batch"],{cwd:t,input:i,maxBuffer:64*1024*1024});if(s.error)throw new Error(`git cat-file --batch failed: ${s.error.message}`);if(s.status!==0)throw new Error(`git cat-file --batch exited with code ${s.status}: ${s.stderr?s.stderr.toString("utf8"):""}`);let o=s.stdout;if(!o||o.length===0)return n;let r=0,a=0;for(;r<o.length&&a<e.length;){let c=o.indexOf(10,r);if(c===-1)break;let d=o.toString("utf8",r,c).trim();r=c+1;let u=d.split(" ");if(u.length>=3&&u[1]==="blob"){let p=parseInt(u[2],10),l=o.subarray(r,r+p);n.set(e[a++],l),r+=p,r<o.length&&o[r]===10&&r++}else a++}return n}function Vt(t){let e=new Map,n=t.split(/^diff --git /m);for(let i of n){if(!i.trim())continue;let r=i.split(/\r?\n/)[0].match(/a\/(.+)\s+b\/(.+)/);if(!r)continue;let a=r[2].trim().replace(/\\/g,"/");if(a==="/dev/null")continue;let c=new Set,d=/^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/gm,u;for(;(u=d.exec(i))!==null;){let p=parseInt(u[1],10),l=u[2]!==void 0?parseInt(u[2],10):1;for(let f=0;f<l;f++)c.add(p+f)}c.size>0?e.set(a,c):(i.includes("rename to ")||i.includes("new file mode ")||i.includes("Binary files "))&&e.set(a,new Set([-1]))}return e}function jt(t,e){if(e.has(-1))return!0;let i=((t.rawSecret||"").match(/\r?\n/g)||[]).length,s=t.line,o=s+i;for(let r=s;r<=o;r++)if(e.has(r))return!0;return!1}function Pn(t){let e=new Set;try{let i=(0,j.execFileSync)("git",[...te,"ls-files","--stage","-z"],{cwd:t,maxBuffer:67108864}).toString("utf8").split("\0");for(let s of i){if(!s)continue;let[o,r]=s.split("	");o&&r&&o.startsWith("160000")&&e.add(r.replace(/\\/g,"/"))}}catch{}return e}async function Nn(t){let e=new Set;try{let{stdout:n}=await Be("git",[...te,"ls-files","--stage","-z"],{cwd:t,maxBuffer:67108864}),i=n.split("\0");for(let s of i){if(!s)continue;let[o,r]=s.split("	");o&&r&&o.startsWith("160000")&&e.add(r.replace(/\\/g,"/"))}}catch{}return e}function Zt(t,e){let n=Tn(t),i;try{i=(0,j.execFileSync)("git",[...te,"diff","--cached","-z","--name-status","--no-color","--no-ext-diff","--src-prefix=a/","--dst-prefix=b/"],{cwd:n,maxBuffer:64*1024*1024})}catch(g){return{status:"ERROR",findings:[],error:`git diff --cached failed: ${g.message||String(g)}`}}let s=Ut(i),o=Pn(n),r=s.filter(g=>g.status!=="D"&&!o.has(g.path));if(r.length===0)return{status:"CLEAN",findings:[],skippedFiles:[],filesScanned:0};let a=[...ot,...rt(n)],c=[],d=[],u=[];for(let g of r){let A=g.path,y=a.find(M=>at(A,M));if(y){d.push({path:A,pattern:y});continue}u.push(A)}if(u.length===0)return{status:"CLEAN",findings:[],skippedFiles:c,ignoredFiles:d,filesScanned:0};let p;try{p=On(n,u)}catch(g){return{status:"ERROR",findings:[],error:g.message||String(g)}}let l=[],f=e?.maxFileSize??Gt;for(let g of u){let A=p.get(g);if(A===void 0)return{status:"ERROR",findings:[],error:`Could not inspect staged blob size for '${g}': buffer truncated or process failed.`};if(A>f){let y=(f/1048576).toFixed(0);if(e?.ignoreSkipped===!0){c.push({path:g,reason:`File size (${(A/(1024*1024)).toFixed(1)}MB) exceeds ${y}MB limit`});continue}return{status:"ERROR",findings:[],error:`File '${g}' (${(A/(1024*1024)).toFixed(1)}MB) exceeds ${y}MB limit. Use --ignore-skipped to bypass.`}}l.push(g)}if(l.length===0)return e?.failOnSkipped&&c.length>0?{status:"ERROR",findings:[],skippedFiles:c,ignoredFiles:d,filesScanned:0,error:`Strict mode (failOnSkipped): ${c.length} file(s) were skipped during staged scan: ${c.map(g=>g.path).join(", ")}`}:{status:"CLEAN",findings:[],skippedFiles:c,ignoredFiles:d,filesScanned:0};let m;try{m=Fn(n,l)}catch(g){return{status:"ERROR",findings:[],error:g.message||String(g)}}let h=new Map;for(let g of l){let A=m.get(g);if(!A)return{status:"ERROR",findings:[],error:`Could not read staged blob for '${g}': buffer truncated or read failed.`};let y=le(A);if(y===null){c.push({path:g,reason:"Binary content detected"});continue}h.set(g,y)}let k=Array.from(h.keys());if(k.length===0)return e?.failOnSkipped&&c.length>0?{status:"ERROR",findings:[],skippedFiles:c,ignoredFiles:d,filesScanned:0,error:`Strict mode (failOnSkipped): ${c.length} file(s) were skipped during staged scan: ${c.map(g=>g.path).join(", ")}`}:{status:"CLEAN",findings:[],skippedFiles:c,ignoredFiles:d,filesScanned:0};let E="",v=50;for(let g=0;g<k.length;g+=v){let A=k.slice(g,g+v);try{let y=(0,j.execFileSync)("git",[...te,"diff","--cached","-U0","--no-color","--no-ext-diff","--no-textconv","--src-prefix=a/","--dst-prefix=b/","--",...A],{cwd:n,encoding:"utf8",maxBuffer:67108864});E+=`
`+y}catch{E="";break}}let C=Vt(E),I=[],O=0;for(let g of k){let A=h.get(g);if(!A)continue;let y=C.get(g)||new Set([-1]),M={workspaceRoot:n,disallowInlineIgnore:e?.disallowInlineIgnore},_=pe(A,g,M);O++;let w=[];for(let R of _)jt(R,y)&&w.push(R);w.length>0&&I.push(...w)}return e?.failOnSkipped&&c.length>0?{status:"ERROR",findings:I,skippedFiles:c,ignoredFiles:d,filesScanned:O,error:`Strict mode (failOnSkipped): ${c.length} file(s) were skipped during staged scan: ${c.map(g=>g.path).join(", ")}`}:{status:I.length>0?"FINDINGS":"CLEAN",findings:I,skippedFiles:c,ignoredFiles:d,filesScanned:O}}async function qt(t,e){let n=await Ln(t),i;try{let{stdout:g}=await Be("git",[...te,"diff","--cached","-z","--name-status","--no-color","--no-ext-diff","--src-prefix=a/","--dst-prefix=b/"],{cwd:n,maxBuffer:67108864,encoding:"buffer"});i=Buffer.isBuffer(g)?g:Buffer.from(g)}catch(g){return{status:"ERROR",findings:[],error:`git diff --cached failed: ${g.message||String(g)}`}}let s=Ut(i),o=await Nn(n),r=s.filter(g=>g.status!=="D"&&!o.has(g.path));if(r.length===0)return{status:"CLEAN",findings:[],skippedFiles:[],filesScanned:0};let a=[...ot,...rt(n)],c=[],d=[],u=[];for(let g of r){let A=g.path,y=a.find(M=>at(A,M));if(y){d.push({path:A,pattern:y});continue}u.push(A)}if(u.length===0)return{status:"CLEAN",findings:[],skippedFiles:c,ignoredFiles:d,filesScanned:0};let p=new Map;try{let g=u.map(w=>`:${w}
`).join(""),A=(0,j.spawn)("git",[...te,"cat-file","--batch-check"],{cwd:n}),y="",M="";A.stdout.on("data",w=>y+=w.toString("utf8")),A.stderr.on("data",w=>M+=w.toString("utf8")),A.stdin.write(g),A.stdin.end(),await new Promise((w,R)=>{A.on("error",R),A.on("close",b=>{b!==0?R(new Error(`git cat-file --batch-check exited with code ${b}: ${M}`)):w()})});let _=y.split(/\r?\n/);for(let w=0;w<u.length;w++){let R=_[w];if(!R)continue;let b=R.split(" ");b.length>=3&&b[1]==="blob"&&p.set(u[w],parseInt(b[2],10)||0)}}catch(g){return{status:"ERROR",findings:[],error:g.message||String(g)}}let l=[],f=e?.maxFileSize??Gt;for(let g of u){let A=p.get(g);if(A===void 0)return{status:"ERROR",findings:[],error:`Could not inspect staged blob size for '${g}': buffer truncated or process failed.`};if(A>f){let y=(f/1048576).toFixed(0);if(e?.ignoreSkipped===!0){c.push({path:g,reason:`File size (${(A/(1024*1024)).toFixed(1)}MB) exceeds ${y}MB limit`});continue}return{status:"ERROR",findings:[],error:`File '${g}' (${(A/(1024*1024)).toFixed(1)}MB) exceeds ${y}MB limit. Use --ignore-skipped to bypass.`}}l.push(g)}if(l.length===0)return e?.failOnSkipped&&c.length>0?{status:"ERROR",findings:[],skippedFiles:c,ignoredFiles:d,filesScanned:0,error:`Strict mode (failOnSkipped): ${c.length} file(s) were skipped during staged scan: ${c.map(g=>g.path).join(", ")}`}:{status:"CLEAN",findings:[],skippedFiles:c,ignoredFiles:d,filesScanned:0};let m=new Map;try{let g=l.map(b=>`:${b}
`).join(""),A=(0,j.spawn)("git",[...te,"cat-file","--batch"],{cwd:n}),y=[],M="";A.stdout.on("data",b=>y.push(b)),A.stderr.on("data",b=>M+=b.toString("utf8")),A.stdin.write(g),A.stdin.end(),await new Promise((b,L)=>{A.on("error",L),A.on("close",$=>{$!==0?L(new Error(`git cat-file --batch exited with code ${$}: ${M}`)):b()})});let _=Buffer.concat(y),w=0,R=0;for(;w<_.length&&R<l.length;){let b=_.indexOf(10,w);if(b===-1)break;let L=_.toString("utf8",w,b).trim();w=b+1;let $=L.split(" ");if($.length>=3&&$[1]==="blob"){let K=parseInt($[2],10),B=_.subarray(w,w+K);m.set(l[R++],B),w+=K,w<_.length&&_[w]===10&&w++}else R++}}catch(g){return{status:"ERROR",findings:[],error:g.message||String(g)}}let h=new Map;for(let g of l){let A=m.get(g);if(!A)return{status:"ERROR",findings:[],error:`Could not read staged blob for '${g}': buffer truncated or read failed.`};let y=le(A);if(y===null){c.push({path:g,reason:"Binary content detected"});continue}h.set(g,y)}let k=Array.from(h.keys());if(k.length===0)return e?.failOnSkipped&&c.length>0?{status:"ERROR",findings:[],skippedFiles:c,ignoredFiles:d,filesScanned:0,error:`Strict mode (failOnSkipped): ${c.length} file(s) were skipped during staged scan: ${c.map(g=>g.path).join(", ")}`}:{status:"CLEAN",findings:[],skippedFiles:c,ignoredFiles:d,filesScanned:0};let E="",v=50;for(let g=0;g<k.length;g+=v){let A=k.slice(g,g+v);try{let{stdout:y}=await Be("git",[...te,"diff","--cached","-U0","--no-color","--no-ext-diff","--no-textconv","--src-prefix=a/","--dst-prefix=b/","--",...A],{cwd:n,encoding:"utf8",maxBuffer:67108864});E+=`
`+y}catch{}}let C=Vt(E),I=[],O=0;for(let g of k){let A=h.get(g);if(!A)continue;let y=C.get(g)||new Set([-1]),M={workspaceRoot:n,disallowInlineIgnore:e?.disallowInlineIgnore},_=pe(A,g,M);O++;let w=[];for(let R of _)jt(R,y)&&w.push(R);w.length>0&&I.push(...w)}return e?.failOnSkipped&&c.length>0?{status:"ERROR",findings:I,skippedFiles:c,ignoredFiles:d,filesScanned:O,error:`Strict mode (failOnSkipped): ${c.length} file(s) were skipped during staged scan: ${c.map(g=>g.path).join(", ")}`}:{status:I.length>0?"FINDINGS":"CLEAN",findings:I,skippedFiles:c,ignoredFiles:d,filesScanned:O}}var lt=["LOW","MEDIUM","HIGH","CRITICAL"],dt={LOW:1,MEDIUM:2,HIGH:3,CRITICAL:4},Z="HIGH";function $n(t){return typeof t=="string"&&lt.includes(t.toUpperCase())}function xe(t,e=Z){return $n(t)?t.toUpperCase():e}function Yt(t,e=Z){return(dt[t]||0)>=(dt[e]||dt.CRITICAL)}var fe="# [SLD_HOOK_MANAGED]";function Jt(t=Z,e,n,i=!0,s=!0,o=!0,r=!1){let a=lt.includes(t)?t:Z,c=e?e.replace(/\\/g,"/"):"",d=c?c.replace(/'/g,"'\\''"):"",u=n?n.replace(/\\/g,"/"):"",p=u?u.replace(/'/g,"'\\''"):"",l=p?`# Resolved Node.js executable (prefer pinned runtime, fallback to system node on PATH)
if [ -n '${p}' ] && [ -x '${p}' ]; then
  NODE_CMD='${p}'
elif command -v node >/dev/null 2>&1; then
  NODE_CMD='node'
elif [ -x '/usr/local/bin/node' ]; then
  NODE_CMD='/usr/local/bin/node'
elif [ -x '/opt/homebrew/bin/node' ]; then
  NODE_CMD='/opt/homebrew/bin/node'
else
  NODE_CMD=''
fi`:`# Resolve Node.js from PATH
if command -v node >/dev/null 2>&1; then
  NODE_CMD='node'
elif [ -x '/usr/local/bin/node' ]; then
  NODE_CMD='/usr/local/bin/node'
elif [ -x '/opt/homebrew/bin/node' ]; then
  NODE_CMD='/opt/homebrew/bin/node'
else
  NODE_CMD=''
fi`,f=c?`# Scanner pinned to bundled CLI path
PINNED_CLI='${d}'
if [ -n "$PINNED_CLI" ] && [ -f "$PINNED_CLI" ]; then
  if [ -z "$NODE_CMD" ]; then
    echo ""
    echo "\u274C COMMIT BLOCKED: Node.js runtime not found on PATH (exit 127)."
    echo "   The pre-commit hook requires Node.js (>=18) to execute the scanner."
    echo "   Ensure 'node' is in your PATH or configure your Git client environment."
    exit 127
  fi
  if ! NODE_MAJOR=$(ELECTRON_RUN_AS_NODE=1 "$NODE_CMD" -p 'process.versions.node.split(".")[0]' 2>/dev/null); then
    echo ""
    echo "\u274C COMMIT BLOCKED: Cannot determine Node.js version. Commit blocked."
    exit 2
  fi
  case "$NODE_MAJOR" in
    ''|*[!0-9]*)
      echo ""
      echo "\u274C COMMIT BLOCKED: Invalid Node.js version. Commit blocked."
      exit 2
      ;;
  esac
  if [ "$NODE_MAJOR" -lt 18 ]; then
    echo ""
    echo "\u274C COMMIT BLOCKED: Node.js 18+ required (v$NODE_MAJOR detected). Commit blocked."
    exit 2
  fi
  ELECTRON_RUN_AS_NODE=1 "$NODE_CMD" "$PINNED_CLI" scan --staged --fail-on "$SLD_FAIL_ON" $DISALLOW_INLINE $IGNORE_SKIPPED $FAIL_ON_SKIPPED
  SCAN_STATUS=$?
elif command -v secret-leak-detector >/dev/null 2>&1; then
  secret-leak-detector scan --staged --fail-on "$SLD_FAIL_ON" $DISALLOW_INLINE $IGNORE_SKIPPED $FAIL_ON_SKIPPED
  SCAN_STATUS=$?
else
  HOOK_PATH="$(git rev-parse --git-path hooks/pre-commit 2>/dev/null || echo "$0")"
  HOOK_DIR="$(dirname "$HOOK_PATH")"
  LATEST_BACKUP="$HOOK_DIR/pre-commit.sld-backup.latest"
  ALLOW_SELF_HEAL=0
  if [ "$SLD_ALLOW_SELF_HEAL" = "1" ] || [ "$SLD_SELF_HEAL" = "1" ] || [ "$SLD_ALLOW_SELF_HEAL_DEFAULT" = "1" ] || [ "$(git config --bool secret-leak-detector.allow-self-heal 2>/dev/null)" = "true" ]; then
    ALLOW_SELF_HEAL=1
  fi

  # If pinned CLI was in an extension/editor folder that was uninstalled, auto-recover ONLY if self-heal is opted into:
  case "$PINNED_CLI" in
    *extensions*|*globalStorage*|*.vscode*|*AppData*|*.config*)
      if [ "$ALLOW_SELF_HEAL" = "1" ]; then
        echo "\u26A0\uFE0F [Secret Leak Detector] Extension was uninstalled (pinned scanner no longer exists)."
        if [ -f "$LATEST_BACKUP" ]; then
          BACKUP_FILE=$(cat "$LATEST_BACKUP" 2>/dev/null)
          if [ -f "$BACKUP_FILE" ]; then
            echo "   Restoring original backed-up pre-commit hook..."
            cp "$BACKUP_FILE" "$HOOK_PATH" 2>/dev/null && rm -f "$LATEST_BACKUP" "$BACKUP_FILE" 2>/dev/null
            if [ -x "$HOOK_PATH" ]; then
              exec "$HOOK_PATH" "$@"
            fi
            exit 0
          fi
        fi
        echo "   Removing stranded pre-commit hook..."
        rm -f "$HOOK_PATH" "$LATEST_BACKUP" 2>/dev/null
        exit 0
      fi
      ;;
  esac
  echo ""
  echo "\u274C COMMIT BLOCKED (fail-closed): Secret Leak Detector scanner is unavailable."
  echo "   Pinned CLI ($PINNED_CLI) not found and no global CLI available."
  echo "   Recovery instructions:"
  echo "     - Remove stranded hook: rm "$HOOK_PATH""
  if [ -f "$LATEST_BACKUP" ]; then
    echo "     - Or restore backup: cp "$LATEST_BACKUP" "$HOOK_PATH""
  fi
  echo "     - Or install CLI globally: npm install -g secret-leak-detector"
  echo "     - Or re-pin hook: open the project in VS Code with Secret Leak Detector installed"
  echo "     - Or allow self-healing hook removal:"
  echo "         SLD_ALLOW_SELF_HEAL=1 git commit"
  echo "         or: git config secret-leak-detector.allow-self-heal true"
  exit 2
fi`:`# Scanner determined from environment or global binary (never ./dist/cli.js relative to repo)
if [ -n "$SLD_CLI_PATH" ] && [ -f "$SLD_CLI_PATH" ]; then
  if [ -z "$NODE_CMD" ]; then
    echo ""
    echo "\u274C COMMIT BLOCKED: Node.js runtime not found on PATH (exit 127)."
    echo "   The pre-commit hook requires Node.js (>=18) to execute the scanner."
    exit 127
  fi
  if ! NODE_MAJOR=$(ELECTRON_RUN_AS_NODE=1 "$NODE_CMD" -p 'process.versions.node.split(".")[0]' 2>/dev/null); then
    echo ""
    echo "\u274C COMMIT BLOCKED: Cannot determine Node.js version. Commit blocked."
    exit 2
  fi
  case "$NODE_MAJOR" in
    ''|*[!0-9]*)
      echo ""
      echo "\u274C COMMIT BLOCKED: Invalid Node.js version. Commit blocked."
      exit 2
      ;;
  esac
  if [ "$NODE_MAJOR" -lt 18 ]; then
    echo ""
    echo "\u274C COMMIT BLOCKED: Node.js 18+ required (v$NODE_MAJOR detected). Commit blocked."
    exit 2
  fi
  ELECTRON_RUN_AS_NODE=1 "$NODE_CMD" "$SLD_CLI_PATH" scan --staged --fail-on "$SLD_FAIL_ON" $DISALLOW_INLINE $IGNORE_SKIPPED $FAIL_ON_SKIPPED
  SCAN_STATUS=$?
elif command -v secret-leak-detector >/dev/null 2>&1; then
  secret-leak-detector scan --staged --fail-on "$SLD_FAIL_ON" $DISALLOW_INLINE $IGNORE_SKIPPED $FAIL_ON_SKIPPED
  SCAN_STATUS=$?
else
  HOOK_PATH="$(git rev-parse --git-path hooks/pre-commit 2>/dev/null || echo "$0")"
  HOOK_DIR="$(dirname "$HOOK_PATH")"
  LATEST_BACKUP="$HOOK_DIR/pre-commit.sld-backup.latest"
  echo ""
  echo "\u274C COMMIT BLOCKED (fail-closed): Secret Leak Detector scanner is unavailable."
  echo "   Pinned CLI not found and no global CLI available."
  echo "   Recovery instructions:"
  echo "     - Remove stranded hook: rm "$HOOK_PATH""
  if [ -f "$LATEST_BACKUP" ]; then
    echo "     - Or restore backup: cp "$LATEST_BACKUP" "$HOOK_PATH""
  fi
  echo "     - Or install CLI globally: npm install -g secret-leak-detector"
  echo "     - Or re-pin hook: open the project in VS Code with Secret Leak Detector installed"
  exit 2
fi`;return`#!/bin/sh
${fe}
# Secret Leak Detector Pre-Commit Hook
# Intercepts git commit and blocks unredacted credentials before they leave the machine.
#
# Severity policy (single source of truth: src/core/policy.ts):
#   Blocks findings at ${a} and above (LOW < MEDIUM < HIGH < CRITICAL).
#   Lower tiers are reported but do not block.
#
# Fail-closed: if the scanner cannot be executed, the commit is BLOCKED.
SLD_FAIL_ON="${a}"
SLD_BLOCK_COMMITS="${i?"1":"0"}"
SLD_DISALLOW_INLINE_DEFAULT="${s?"1":"0"}"
SLD_FAIL_ON_SKIPPED_DEFAULT="${o?"1":"0"}"
SLD_ALLOW_SELF_HEAL_DEFAULT="${r?"1":"0"}"

echo "\u{1F510} [Secret Leak Detector] Inspecting staged changes for credentials..."

DISALLOW_INLINE=""
if [ "$SLD_ALLOW_INLINE_IGNORE" != "1" ] && [ "$(git config --bool secret-leak-detector.allow-inline-ignore 2>/dev/null)" != "true" ]; then
  if [ "$SLD_DISALLOW_INLINE_IGNORE" = "1" ] || [ "$SLD_DISALLOW_INLINE_DEFAULT" = "1" ] || [ "$(git config --bool secret-leak-detector.disallow-inline-ignore 2>/dev/null)" = "true" ]; then
    DISALLOW_INLINE="--no-inline-ignore"
  fi
fi

IGNORE_SKIPPED=""
if [ "$SLD_IGNORE_SKIPPED" = "1" ] || [ "$(git config --bool secret-leak-detector.ignore-skipped 2>/dev/null)" = "true" ]; then
  IGNORE_SKIPPED="--ignore-skipped"
fi

FAIL_ON_SKIPPED=""
if [ "$SLD_IGNORE_SKIPPED" != "1" ] && [ "$(git config --bool secret-leak-detector.ignore-skipped 2>/dev/null)" != "true" ] && [ "$(git config --bool secret-leak-detector.strict 2>/dev/null)" != "false" ] && [ "$(git config --bool secret-leak-detector.fail-on-skipped 2>/dev/null)" != "false" ]; then
  if [ "$SLD_FAIL_ON_SKIPPED" = "1" ] || [ "$SLD_FAIL_ON_SKIPPED_DEFAULT" = "1" ] || [ "$SLD_STRICT" = "1" ] || [ "$(git config --bool secret-leak-detector.fail-on-skipped 2>/dev/null)" = "true" ] || [ "$(git config --bool secret-leak-detector.strict 2>/dev/null)" = "true" ]; then
    FAIL_ON_SKIPPED="--fail-on-skipped"
  fi
fi

${l}

${f}

if [ "$SCAN_STATUS" -eq 1 ]; then
  if [ "$SLD_BLOCK_COMMITS" = "0" ]; then
    echo ""
    echo "\u26A0\uFE0F WARNING: Secret Leak Detector detected credentials in staged files (commit blocking is disabled in settings)."
  else
    echo ""
    echo "\u274C COMMIT BLOCKED: Secret Leak Detector detected credentials in staged files!"
    echo "Please rotate the secret or migrate it to an environment variable."
    exit 1
  fi
elif [ "$SCAN_STATUS" -eq 127 ]; then
  echo ""
  echo "\u274C COMMIT BLOCKED: Node.js executable not found on PATH (exit 127)."
  echo "   If using a GUI Git client or nvm, ensure 'node' is available in the shell PATH."
  exit 2
elif [ "$SCAN_STATUS" -ne 0 ]; then
  echo ""
  echo "\u274C COMMIT BLOCKED (fail-closed): Scanner exited with error ($SCAN_STATUS)."
  echo "   If a file could not be read or inspected, you can bypass with:"
  echo "     SLD_IGNORE_SKIPPED=1 git commit"
  echo "     or: git config secret-leak-detector.ignore-skipped true"
  echo "   To configure strict blocking behavior:"
  echo "     secret-leak-detector hook install --strict"
  echo "     or: git config secret-leak-detector.strict true"
  echo "   To disable strict blocking behavior:"
  echo "     git config secret-leak-detector.strict false (warn on skipped)"
  exit 2
fi

# Chain an existing user hook if it was previously backed up.
# Executes directly when executable to support Python, Node, and Husky hooks.
HOOKS_DIR="$(cd "$(dirname "$0")" && pwd)"
LATEST_MARKER="$HOOKS_DIR/pre-commit.sld-backup.latest"
if [ -f "$LATEST_MARKER" ]; then
  BACKUP_HOOK=$(cat "$LATEST_MARKER")
  if [ -f "$BACKUP_HOOK" ]; then
    echo "\u{1F517} Running chained pre-commit hook..."
    if [ -x "$BACKUP_HOOK" ]; then
      exec "$BACKUP_HOOK" "$@"
    else
      sh "$BACKUP_HOOK" "$@"
      exit $?
    fi
  fi
fi

exit 0
`}var Xt=(0,Qt.promisify)(We.execFile);function He(t){try{let e=P.join(pt.homedir(),".sld");x.existsSync(e)||x.mkdirSync(e,{recursive:!0});let n=P.join(e,"installed-hooks.json"),i=[];if(x.existsSync(n))try{let o=JSON.parse(x.readFileSync(n,"utf8"));Array.isArray(o)&&(i=o.filter(r=>typeof r=="string"))}catch(o){console.warn(`[Secret Leak Detector] Warning reading installed hooks registry: ${o?.message||o}`)}let s=P.resolve(t);i.includes(s)||(i.push(s),x.writeFileSync(n,JSON.stringify(i,null,2),"utf8"))}catch(e){console.warn(`[Secret Leak Detector] Warning updating installed hooks registry: ${e?.message||e}`)}}function Ke(t){try{let e=P.join(pt.homedir(),".sld","installed-hooks.json");if(x.existsSync(e)){let n=JSON.parse(x.readFileSync(e,"utf8"));if(Array.isArray(n)){let i=P.resolve(t),s=n.filter(o=>typeof o=="string"&&P.resolve(o)!==i);x.writeFileSync(e,JSON.stringify(s,null,2),"utf8")}}}catch(e){console.warn(`[Secret Leak Detector] Warning unrecording hook from registry: ${e?.message||e}`)}}var ae=class{workspaceRoot;cliPath;onWarn;constructor(e,n,i){if(this.workspaceRoot=e,typeof n=="function"?this.onWarn=n:n&&x.existsSync(n)?(this.cliPath=n,this.onWarn=i):this.onWarn=i,!this.cliPath)if(process.env.SLD_CLI_PATH&&x.existsSync(process.env.SLD_CLI_PATH))this.cliPath=process.env.SLD_CLI_PATH;else{let s=[P.resolve(__dirname,"cli.js"),P.resolve(__dirname,"../cli/index.js"),P.resolve(__dirname,"../../dist/cli.js")];this.cliPath=s.find(o=>x.existsSync(o))}}async isGitRepo(){try{return await Xt("git",["rev-parse","--is-inside-work-tree"],{cwd:this.workspaceRoot}),!0}catch{return!1}}async scanStagedChanges(e){return qt(this.workspaceRoot,e)}scanStagedChangesSync(e){return Zt(this.workspaceRoot,e)}formatTerminalBlockedMessage(e){let i=e.filter(c=>c.risk==="CRITICAL")[0]||e[0],s=typeof i.remediation=="string"?i.remediation:i.remediation?.steps?.join(`
`)||"Rotate and move to .env",o=i.evidence?.items?.map(c=>`  - [${c.confidenceImpact>=0?"+":""}${c.confidenceImpact}] ${c.description}`).join(`
`)||i.signals?.map(c=>`  - ${c}`).join(`
`)||"  - Known pattern match",r=i.riskAssessment?.blastRadius?`${i.riskAssessment.blastRadius.level} (${i.riskAssessment.blastRadius.summary})`:"Local Working Tree";return`
============================================================
\u274C COMMIT BLOCKED BY SECRET LEAK DETECTOR
============================================================
\u{1F6A8} Security Risk: Hard-coded secret detected before commit!

Finding Details:
------------------------------------------------------------
\u2022 Type:        ${i.type}
\u2022 Provider:    ${i.provider}
\u2022 File:        ${i.file} (Line ${i.line})
\u2022 Secret:      ${i.redactedSecret}
\u2022 Risk Level:  ${i.risk} (Score: ${i.riskAssessment?.score??95}/100)
\u2022 Confidence:  ${i.confidence}%
\u2022 Blast Radius: ${r}

Evidence & Signals Detected:
${o}

Recommended Remediation:
------------------------------------------------------------
${s}

Example Fix:
  ${i.exampleFix||i.remediation?.replacementCode}

After fixing:
  1. Replace the secret in ${i.file} with an environment variable.
  2. Add the sensitive value to your local .env (ensure .env is in .gitignore!).
  3. Run 'git add ${i.file}'
  4. Run your 'git commit' again.
============================================================
`}async resolveHooksDir(){try{let{stdout:e}=await Xt("git",["rev-parse","--git-path","hooks"],{cwd:this.workspaceRoot}),n=e.trim();return P.isAbsolute(n)?n:P.resolve(this.workspaceRoot,n)}catch{return P.join(this.workspaceRoot,".git","hooks")}}async getHookPath(){let e=await this.resolveHooksDir();return P.join(e,"pre-commit")}async installPreCommitHook(e,n,i=!0,s=Z,o=!0,r=!0,a=!1){if(!await this.isGitRepo())return{success:!1,message:"Workspace is not a Git repository."};let c=e||this.cliPath;if(!c||!x.existsSync(c))return{success:!1,message:`Cannot install pre-commit hook: bundled CLI binary not found at '${c||"undefined"}'. Installation aborted.`};let d=await this.resolveHooksDir();if(!x.existsSync(d))try{x.mkdirSync(d,{recursive:!0})}catch(p){return{success:!1,message:`Could not create hooks directory (${d}): ${p}`}}let u=P.join(d,"pre-commit.sld.lock");try{x.writeFileSync(u,String(process.pid),{flag:"wx"})}catch(p){if(p?.code==="EEXIST")try{let l=x.statSync(u);if(Date.now()-l.mtimeMs>1e4)x.unlinkSync(u),x.writeFileSync(u,String(process.pid),{flag:"wx"});else return{success:!1,message:"Another hook operation is currently in progress (lock active)."}}catch{return{success:!1,message:"Another hook operation is currently in progress (lock active)."}}else return{success:!1,message:`Could not acquire hook lock: ${p?.message||p}`}}try{let p=P.join(d,"pre-commit"),l=Date.now(),f=P.join(d,`pre-commit.sld-backup.${l}`),m=P.join(d,"pre-commit.sld-backup.latest"),h=fe;if(x.existsSync(p))try{let v=x.statSync(p).mode,C=x.readFileSync(p,"utf8");if(!C.includes(h)){let I=`${f}.tmp.${process.pid}`;x.writeFileSync(I,C,{mode:v}),x.renameSync(I,f);let O=`${m}.tmp.${process.pid}`;x.writeFileSync(O,f,"utf8"),x.renameSync(O,m)}}catch(E){return{success:!1,message:`Could not backup existing hook: ${E}`}}if(/[\/\\](?:_npx|Temp|tmp)[\/\\]/i.test(c)){let E=`\u26A0\uFE0F Warning: Pre-commit hook is pinning a temporary/npx CLI path: '${c}'. This path may be deleted automatically by your system. Consider installing secret-leak-detector globally or locally.`;this.onWarn?this.onWarn(E):console.warn(E)}let k=Jt(s,c,n,i,o,r,a);try{let E=P.join(d,`pre-commit.tmp.${process.pid}`);return x.writeFileSync(E,k,{mode:493}),x.renameSync(E,p),He(p),{success:!0,message:`Pre-commit hook successfully installed to ${p}`}}catch(E){return{success:!1,message:`Failed to write hook file: ${E}`}}}finally{try{x.existsSync(u)&&x.unlinkSync(u)}catch{}}}async ensureHookIsPinned(e,n,i=!0,s=Z,o=!0,r=!0,a=!1){if(!e||!x.existsSync(e)||!await this.isGitRepo())return!1;let c=await this.resolveHooksDir(),d=P.join(c,"pre-commit");if(!x.existsSync(d))return!1;try{let u=x.readFileSync(d,"utf8");if(!u.includes(fe))return!1;let p=e.replace(/\\/g,"/"),l=r;if(!l)try{(0,We.execFileSync)("git",["config","--bool","secret-leak-detector.strict"],{cwd:this.workspaceRoot,encoding:"utf8",stdio:["ignore","pipe","ignore"]}).trim()==="true"&&(l=!0)}catch{}let f=`SLD_FAIL_ON="${s}"`,m=`SLD_BLOCK_COMMITS="${i?"1":"0"}"`,h=`SLD_DISALLOW_INLINE_DEFAULT="${o?"1":"0"}"`,k=`SLD_FAIL_ON_SKIPPED_DEFAULT="${l?"1":"0"}"`,E=`SLD_ALLOW_SELF_HEAL_DEFAULT="${a?"1":"0"}"`,v=u.includes("ELECTRON_RUN_AS_NODE=1");if(!u.includes(p)||!u.includes(f)||!u.includes(m)||!u.includes(h)||!u.includes(k)||!u.includes(E)||!v)return(await this.installPreCommitHook(e,n,i,s,o,l,a)).success}catch{return!1}return!0}async uninstallPreCommitHook(){let e=await this.resolveHooksDir(),n=P.join(e,"pre-commit"),i=P.join(e,"pre-commit.sld-backup.latest"),s=P.join(e,"pre-commit.sld.lock");if(!x.existsSync(n))return{success:!0,message:"No pre-commit hook found to uninstall."};try{x.writeFileSync(s,String(process.pid),{flag:"wx"})}catch(o){if(o?.code==="EEXIST")try{let r=x.statSync(s);if(Date.now()-r.mtimeMs>1e4)x.unlinkSync(s),x.writeFileSync(s,String(process.pid),{flag:"wx"});else return{success:!1,message:"Another hook operation is currently in progress (lock active)."}}catch{return{success:!1,message:"Another hook operation is currently in progress (lock active)."}}else return{success:!1,message:`Could not acquire hook lock: ${o?.message||o}`}}try{if(!x.readFileSync(n,"utf8").includes(fe))return{success:!1,message:"Existing pre-commit hook is not managed by Secret Leak Detector; refusing to delete user hook."};if(x.existsSync(i)){let r=x.readFileSync(i,"utf8").trim(),a=P.resolve(r),c=P.resolve(e),d=P.basename(a);if(P.dirname(a)===c&&/^pre-commit\.sld-backup\.\d+$/.test(d)&&x.existsSync(a)){let u=x.statSync(a),p=P.join(e,`pre-commit.restore.tmp.${process.pid}`);x.copyFileSync(a,p);try{x.chmodSync(p,u.mode)}catch{}return x.renameSync(p,n),x.unlinkSync(a),x.unlinkSync(i),Ke(n),{success:!0,message:"Uninstalled SLD hook and restored original pre-commit hook."}}else try{x.unlinkSync(i)}catch{}}return x.unlinkSync(n),Ke(n),{success:!0,message:"Removed Secret Leak Detector pre-commit hook."}}catch(o){return{success:!1,message:`Failed to uninstall hook: ${o.message}`}}finally{try{x.existsSync(s)&&x.unlinkSync(s)}catch{}}}};var W,we=new Map;function Dn(t){W=S.window.createOutputChannel("Secret Leak Detector"),t.subscriptions.push(W),W.appendLine("\u{1F510} [Secret Leak Detector] Extension activated.");let e=new Pe;t.subscriptions.push(e),t.subscriptions.push(S.languages.registerCodeActionsProvider([{scheme:"file"},{scheme:"untitled"}],new ve(e),{providedCodeActionKinds:ve.providedCodeActionKinds}));let n=new Ne,i=new $e;t.subscriptions.push(n),t.subscriptions.push(i),t.subscriptions.push(S.window.registerTreeDataProvider("secret-leak-detector.findingsView",n)),t.subscriptions.push(S.window.registerTreeDataProvider("secret-leak-detector.overviewView",i));let s=S.workspace.workspaceFolders?.[0],o=s?s.uri.fsPath:process.cwd(),r=new ae(o,l=>W.appendLine(l));e.onFindingsChanged(l=>{n.updateFindings(l),i.update(l.length,!0),ue.currentPanel&&ue.currentPanel.updateFindings(l)});let a=()=>S.workspace.getConfiguration("secretLeakDetector");function c(){let f=a().get("minEntropy");e.setMinEntropy(typeof f=="number"&&f>0?f:void 0);let m=t.workspaceState.get("ignoredFindings",[]);e.setIgnoredFindings(m)}c();let d=q.join(t.extensionPath,"dist","cli.js");try{let l=t.globalStorageUri.fsPath;F.existsSync(l)||F.mkdirSync(l,{recursive:!0});let f=q.join(l,"cli.js");F.existsSync(d)&&((!F.existsSync(f)||F.statSync(d).size!==F.statSync(f).size)&&F.copyFileSync(d,f),d=f)}catch{}async function u(){try{let l=t.globalStorageUri.fsPath,f=q.join(t.extensionPath,"dist","ast-parser.js"),m=q.join(l,"ast-parser.js");if(F.existsSync(f)){let h=!0;if(F.existsSync(m)){let k=await F.promises.stat(f),E=await F.promises.stat(m);k.size===E.size&&k.mtimeMs<=E.mtimeMs&&(h=!1)}h&&(F.existsSync(l)||await F.promises.mkdir(l,{recursive:!0}),await F.promises.copyFile(f,m))}}catch{}}async function p(l){let f=S.workspace.workspaceFolders||[],m=a().get("blockGitCommits",!0),h=xe(a().get("failOn",Z)),k=a().get("disallowInlineIgnore",!0),E=a().get("strict",!1)||a().get("failOnSkipped",!1),v=q.join(t.globalStorageUri.fsPath,"installed-hooks.json"),C=[];try{if(F.existsSync(v)){let g=JSON.parse(F.readFileSync(v,"utf8"));Array.isArray(g)&&(C=g.filter(A=>typeof A=="string"))}}catch{}let I=new Set(C),O=!1;for(let g of f){let A=new ae(g.uri.fsPath,y=>W.appendLine(y));if(await A.isGitRepo()){let y=await A.getHookPath().catch(()=>""),M=!1;if(y&&F.existsSync(y))try{M=F.readFileSync(y,"utf8").includes(fe)}catch{}M&&(O||(await u(),O=!0),await A.ensureHookIsPinned(l,process.execPath,m,h,k,E).catch(()=>{}),I.add(y))}}try{F.writeFileSync(v,JSON.stringify(Array.from(I),null,2),"utf8")}catch{}}F.existsSync(d)&&p(d).catch(()=>{}),t.subscriptions.push(S.workspace.onDidChangeWorkspaceFolders(async()=>{F.existsSync(d)&&await p(d).catch(()=>{})})),t.subscriptions.push(S.workspace.onDidChangeConfiguration(l=>{l.affectsConfiguration("secretLeakDetector")&&(c(),F.existsSync(d)&&p(d).catch(()=>{}),S.window.activeTextEditor&&e.scanDocument(S.window.activeTextEditor.document))})),S.window.activeTextEditor&&e.scanDocument(S.window.activeTextEditor.document),t.subscriptions.push(S.workspace.onDidSaveTextDocument(l=>{a().get("enableRealtimeScanning",!0)&&e.scanDocument(l)})),t.subscriptions.push(S.workspace.onDidOpenTextDocument(l=>{a().get("enableRealtimeScanning",!0)&&e.scanDocument(l)})),t.subscriptions.push(S.workspace.onDidChangeTextDocument(l=>{if(!a().get("enableRealtimeScanning",!0))return;let f=l.document.uri.toString(),m=we.get(f);m&&clearTimeout(m);let h=setTimeout(()=>{e.scanDocument(l.document),we.delete(f)},350);we.set(f,h)})),t.subscriptions.push(S.workspace.onDidDeleteFiles(l=>{l.files.forEach(f=>e.removeDocument(f))})),t.subscriptions.push(S.workspace.onDidRenameFiles(l=>{l.files.forEach(f=>e.renameDocument(f.oldUri,f.newUri))})),t.subscriptions.push(S.commands.registerCommand("secret-leak-detector.scanWorkspace",async()=>{if(!S.workspace.workspaceFolders||S.workspace.workspaceFolders.length===0){S.window.showWarningMessage("Please open a workspace folder or repository to scan for secrets.");return}await S.window.withProgress({location:S.ProgressLocation.Notification,title:"\u{1F510} Scanning workspace for secret leaks...",cancellable:!0},async(l,f)=>{let m=a().get("excludeGlobs",[]),h=m.length>0?`{${m.join(",")}}`:void 0,k=1e3,E=await S.workspace.findFiles("**/*",h,k),v=new Map,C=[],I=0,O=0,g=E.length;for(let R=0;R<g;R++){if(f.isCancellationRequested){S.window.showInformationMessage("Secret Leak Detector: Workspace scan was cancelled.");return}let b=E[R],L=q.extname(b.fsPath).toLowerCase();if(st.has(L)){O++;continue}try{if((await S.workspace.fs.stat(b)).size>50*1024*1024){O++;continue}let K=await S.workspace.fs.readFile(b),B=le(Buffer.from(K));if(B===null){O++;continue}let G=S.workspace.getWorkspaceFolder(b),U={workspaceRoot:G?G.uri.fsPath:void 0,minEntropyThreshold:a().get("minEntropy")},J=pe(B,b.fsPath,U);v.set(b.fsPath,J),C.push(...J),I++}catch{O++}l.report({message:`${I}/${g} files scanned`,increment:1/(g||1)*100})}let A=E.length>=k;A?e.mergeBatchFindings(v):e.setBatchFindings(v);let y=`Scanned ${I} files.`;A&&(y+=` \u26A0\uFE0F Scan was capped at ${k} files.`),O>0&&(y+=` (${O} large or binary files skipped)`);let M=new Set(e.getIgnoredFindings()),_=C.filter(R=>!M.has(R.id)),w;if(_.length>0?w="FINDINGS":A||O>0||I===0?w="INCOMPLETE":w="CLEAN",w==="FINDINGS"){let R=_.filter(b=>b.risk==="CRITICAL").length;S.window.showErrorMessage(`\u{1F6A8} Found ${_.length} leaked secret(s) (${R} Critical)! ${y}`,"Open Dashboard","View Findings").then(b=>{b==="Open Dashboard"?S.commands.executeCommand("secret-leak-detector.openDashboard"):b==="View Findings"&&S.commands.executeCommand("workbench.view.extension.secret-leak-detector-sidebar")})}else w==="INCOMPLETE"?S.window.showWarningMessage(`\u26A0\uFE0F Incomplete workspace scan: ${y} No credentials detected in inspected files, but inspection was not exhaustive.`):S.window.showInformationMessage(`\u2705 Workspace scan clean: ${y} No unignored secrets or credentials detected!`)})})),t.subscriptions.push(S.commands.registerCommand("secret-leak-detector.scanStaged",async()=>{let l=S.workspace.workspaceFolders||[];if(l.length===0){S.window.showWarningMessage("Please open a Git repository in VS Code to scan staged changes.");return}W.clear(),W.appendLine("\u{1F510} [Secret Leak Detector] Scanning Git staged changes..."),W.show(!0);let f=a().get("blockGitCommits",!0),m=xe(a().get("failOn",Z)),h=a().get("ignoreSkipped",!0),k=a().get("failOnSkipped",!1),E=new Set;for(let _ of l)await new ae(_.uri.fsPath).isGitRepo()&&E.add(_.uri.fsPath);if(E.size===0){S.window.showWarningMessage("None of the opened workspace folders are Git repositories.");return}let v=[],C=[],I=[];for(let _ of E){let R=await new ae(_,b=>W.appendLine(b)).scanStagedChanges({ignoreSkipped:h,failOnSkipped:k});R.status==="ERROR"&&I.push(`${_}: ${R.error}`),R.skippedFiles&&C.push(...R.skippedFiles),R.findings&&v.push(...R.findings)}if(I.length>0){let _=`\u274C Git scan encountered error(s):
${I.join(`
`)}`;W.appendLine(_),S.window.showErrorMessage(_,"View Output").then(w=>{w==="View Output"&&W.show(!0)});return}if(C.length>0){W.appendLine(`\u2139\uFE0F  Skipped ${C.length} binary or oversized file(s):`);for(let _ of C)W.appendLine(`   \u2022 ${_.path}: ${_.reason}`)}if(v.length===0){C.length>0?(W.appendLine(`\u26A0\uFE0F  Staged scan completed with warnings: ${C.length} uninspected file(s) skipped.`),S.window.showWarningMessage(`\u26A0\uFE0F Git staged changes scanned with warnings: ${C.length} uninspected file(s) skipped.`)):(W.appendLine("\u2705 All staged changes are clean! No credentials detected."),S.window.showInformationMessage("\u2705 Git staged changes are safe to commit."));return}let O=v.filter(_=>Yt(_.risk,m)),A=new ae(o).formatTerminalBlockedMessage(O.length>0?O:v);W.appendLine(A);let M=f&&O.length>0?`\u274C COMMIT BLOCKED: ${O.length} secret(s) at or above ${m} detected in staged changes!`:`\u26A0\uFE0F WARNING: ${v.length} secret(s) detected in staged changes (none block at the ${m} threshold).`;S.window.showErrorMessage(M,"Open Dashboard","View Output").then(_=>{_==="Open Dashboard"?ue.createOrShow(t.extensionUri,v):_==="View Output"&&W.show(!0)})})),t.subscriptions.push(S.commands.registerCommand("secret-leak-detector.openDashboard",()=>{ue.createOrShow(t.extensionUri,e.getAllFindings())})),t.subscriptions.push(S.commands.registerCommand("secret-leak-detector.installGitHook",async()=>{if((S.workspace.workspaceFolders||[]).length===0){S.window.showWarningMessage("Please open a Git repository in VS Code before installing the pre-commit hook.");return}let f=a().get("blockGitCommits",!0),m=xe(a().get("failOn",Z)),h=a().get("disallowInlineIgnore",!0),k=a().get("failOnSkipped",!1);await u();let E=await r.installPreCommitHook(d,process.execPath,f,m,h,k);if(E.success){try{let v=q.join(t.globalStorageUri.fsPath,"installed-hooks.json"),C=await r.getHookPath(),I=[];if(F.existsSync(v)){let O=JSON.parse(F.readFileSync(v,"utf8"));Array.isArray(O)&&(I=O.filter(g=>typeof g=="string"))}I.includes(C)||(I.push(C),F.writeFileSync(v,JSON.stringify(I,null,2),"utf8")),He(C)}catch(v){W.appendLine(`[Registry] Error updating hooks record: ${v?.message||v}`)}S.window.showInformationMessage(`\u{1F6E1}\uFE0F ${E.message}`)}else S.window.showErrorMessage(`Failed to install hook: ${E.message}`)})),t.subscriptions.push(S.commands.registerCommand("secret-leak-detector.installGitHookStrict",async()=>{if((S.workspace.workspaceFolders||[]).length===0){S.window.showWarningMessage("Please open a Git repository in VS Code before installing the pre-commit hook.");return}let f=a().get("blockGitCommits",!0),m=xe(a().get("failOn",Z));await u();let h=await r.installPreCommitHook(d,process.execPath,f,m,!0,!0);if(h.success){try{let k=q.join(t.globalStorageUri.fsPath,"installed-hooks.json"),E=await r.getHookPath(),v=[];if(F.existsSync(k)){let C=JSON.parse(F.readFileSync(k,"utf8"));Array.isArray(C)&&(v=C.filter(I=>typeof I=="string"))}v.includes(E)||(v.push(E),F.writeFileSync(k,JSON.stringify(v,null,2),"utf8")),He(E)}catch(k){W.appendLine(`[Registry] Error updating hooks record: ${k?.message||k}`)}S.window.showInformationMessage(`\u{1F6E1}\uFE0F ${h.message} (Strict Mode: Fail on Skipped & No Inline Ignore)`)}else S.window.showErrorMessage(`Failed to install hook: ${h.message}`)})),t.subscriptions.push(S.commands.registerCommand("secret-leak-detector.uninstallGitHook",async()=>{if((S.workspace.workspaceFolders||[]).length===0){S.window.showWarningMessage("Please open a Git repository in VS Code before uninstalling the pre-commit hook.");return}let f=await r.getHookPath(),m=await r.uninstallPreCommitHook();if(m.success){try{let h=q.join(t.globalStorageUri.fsPath,"installed-hooks.json");if(F.existsSync(h)){let k=JSON.parse(F.readFileSync(h,"utf8"));if(Array.isArray(k)){let E=k.filter(v=>v!==f);F.writeFileSync(h,JSON.stringify(E,null,2),"utf8")}}Ke(f)}catch(h){W.appendLine(`[Registry] Error updating hooks record: ${h?.message||h}`)}S.window.showInformationMessage(`\u{1F6E1}\uFE0F ${m.message}`)}else S.window.showErrorMessage(`Failed to uninstall hook: ${m.message}`)})),t.subscriptions.push(S.commands.registerCommand("secret-leak-detector.ignoreFinding",async l=>{let f=l;if(!f){let E=e.getAllFindings();if(E.length===0){S.window.showInformationMessage("No active findings to ignore.");return}let v=await S.window.showQuickPick(E.map(C=>({label:`${C.type} (${C.file}:${C.line})`,description:C.redactedSecret,id:C.id})),{placeHolder:"Select a finding to ignore (suppress as false-positive)"});if(!v)return;f=v.id}e.ignoreFinding(f);let m=e.getIgnoredFindings();await t.workspaceState.update("ignoredFindings",m);let k=e.getAllFindings().find(E=>E.id===f);if(k){let E=t.workspaceState.get("ignoredFindingsMeta",{});E[f]={type:k.type,file:k.file,line:k.line,secret:k.redactedSecret},await t.workspaceState.update("ignoredFindingsMeta",E)}S.window.showInformationMessage("\u{1F6E1}\uFE0F Finding marked as false-positive and suppressed.")})),t.subscriptions.push(S.commands.registerCommand("secret-leak-detector.unignoreFinding",async()=>{let l=e.getIgnoredFindings();if(l.length===0){S.window.showInformationMessage("No suppressed findings to restore.");return}let f=t.workspaceState.get("ignoredFindingsMeta",{}),m=l.map(E=>{let v=f[E];return{label:v?`${v.type} (${v.secret})`:E,description:v?`${q.basename(v.file)}:${v.line}`:void 0,detail:v?v.file:E,id:E}}),h=await S.window.showQuickPick(m,{placeHolder:"Select a suppressed finding to restore"});if(!h)return;let k=l.filter(E=>E!==h.id);e.setIgnoredFindings(k),await t.workspaceState.update("ignoredFindings",k),delete f[h.id],await t.workspaceState.update("ignoredFindingsMeta",f),S.window.activeTextEditor&&e.scanDocument(S.window.activeTextEditor.document),S.window.showInformationMessage(`\u{1F6E1}\uFE0F Restored finding '${h.label}'.`)})),t.subscriptions.push(S.commands.registerCommand("secret-leak-detector.remediateFinding",async(l,f,m)=>{await ve.executeRemediation(l,f,m)})),t.subscriptions.push(S.commands.registerCommand("secret-leak-detector.clearFindings",()=>{e.clear(),S.window.showInformationMessage("Secret Leak Detector: All findings cleared.")})),r.isGitRepo().then(l=>{i.update(0,l)})}function Mn(){for(let t of we.values())clearTimeout(t);we.clear()}0&&(module.exports={activate,deactivate});
