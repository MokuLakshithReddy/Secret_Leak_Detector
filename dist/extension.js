"use strict";var Jt=Object.create;var we=Object.defineProperty;var Xt=Object.getOwnPropertyDescriptor;var Qt=Object.getOwnPropertyNames;var en=Object.getPrototypeOf,tn=Object.prototype.hasOwnProperty;var nn=(t,e)=>{for(var n in e)we(t,n,{get:e[n],enumerable:!0})},dt=(t,e,n,i)=>{if(e&&typeof e=="object"||typeof e=="function")for(let o of Qt(e))!tn.call(t,o)&&o!==n&&we(t,o,{get:()=>e[o],enumerable:!(i=Xt(e,o))||i.enumerable});return t};var L=(t,e,n)=>(n=t!=null?Jt(en(t)):{},dt(e||!t||!t.__esModule?we(n,"default",{value:t,enumerable:!0}):n,t)),sn=t=>dt(we({},"__esModule",{value:!0}),t);var Pn={};nn(Pn,{activate:()=>Rn,deactivate:()=>Tn});module.exports=sn(Pn);var h=L(require("vscode")),Z=L(require("path")),N=L(require("fs"));var F=L(require("vscode"));var ge=L(require("path")),Dt=L(require("crypto"));var lt=[{id:"aws-access-key",name:"AWS Access Key ID",provider:"Amazon Web Services",pattern:/\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b/g,baseConfidence:98,baseRiskWeight:95,signals:["AWS IAM standard 20-character key prefix (AKIA/ASIA/ABIA/ACCA)","Deterministic uppercase alphanumeric structure","Direct cloud resource control & hijacking capability"],suggestedEnvName:()=>"AWS_ACCESS_KEY_ID",remediationInstructions:["Revoke the exposed Access Key ID immediately in AWS IAM Management Console.","Check AWS CloudTrail logs for unauthorized API calls originated by this key.","Transition to IAM Roles for Amazon EC2 or AWS IAM Identity Center (SSO).","Never store access keys in source code; use AWS_ACCESS_KEY_ID environment variable."]},{id:"aws-secret-key",name:"AWS Secret Access Key",provider:"Amazon Web Services",pattern:/["']?(?:aws_secret_access_key|aws_secret_key|secret_access_key)["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?(?:[\s\r\n;,)]|$)/gi,baseConfidence:94,baseRiskWeight:95,minEntropy:4.1,signals:["Contextual AWS credential parameter match","High-entropy 40-character Base64 payload","Pairs with AWS Access Key for root/IAM API authentication"],suggestedEnvName:()=>"AWS_SECRET_ACCESS_KEY",remediationInstructions:["Rotate the key pair immediately in the AWS IAM Console.","Audit AWS KMS and S3 bucket accesses during exposure window.","Store secrets in AWS Secrets Manager or Parameter Store."]},{id:"github-pat",name:"GitHub Personal Access Token",provider:"GitHub",pattern:/\b(gh[pousr]_[A-Za-z0-9_]{36,255}|github_pat_[A-Za-z0-9_]{82})\b/g,baseConfidence:99,baseRiskWeight:95,signals:["Official GitHub token format prefix (ghp_, gho_, ghu_, ghs_, github_pat_)","Deterministic token structure and length","Permits repository code modification, workflow execution, or release poisoning"],suggestedEnvName:()=>"GITHUB_TOKEN",remediationInstructions:["Revoke token immediately at https://github.com/settings/tokens.","Check GitHub Security Audit Log for unauthorized repository clones or writes.","Use GitHub fine-grained PATs with scoped repository permissions.","Use GitHub Actions secrets rather than personal tokens for CI/CD."]},{id:"google-api-key",name:"Google Cloud / Gemini API Key",provider:"Google Cloud",pattern:/\b(AIza[0-9A-Za-z_-]{34,35})\b/g,baseConfidence:96,baseRiskWeight:90,minEntropy:3.5,signals:["Google standard AIza service key signature","Fixed 39-character alphanumeric structure","Access to Google Cloud Platform APIs and billing services"],suggestedEnvName:()=>"GEMINI_API_KEY",remediationInstructions:["Restrict or delete the API key in Google Cloud Console Credentials page.","Apply API restrictions (e.g. restrict solely to Generative Language API).","Apply HTTP referrer or IP address restrictions.","Store in GEMINI_API_KEY environment variable."]},{id:"google-oauth-token",name:"Google OAuth Access Token",provider:"Google Cloud",pattern:/\b(ya29\.[0-9a-zA-Z_-]{50,150})\b/g,baseConfidence:98,baseRiskWeight:92,minEntropy:4,signals:["Google OAuth bearer access token prefix (ya29.)","Direct user account delegation & Cloud Platform API access"],suggestedEnvName:()=>"GOOGLE_OAUTH_TOKEN",remediationInstructions:["Revoke token via Google Cloud IAM or OAuth2 token revocation endpoint.","Store OAuth refresh tokens securely in credential vaults."]},{id:"openai-api-key",name:"OpenAI API Key",provider:"OpenAI",pattern:/\b(sk-(?:proj|admin|svcacct)-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{20,48})\b/g,baseConfidence:97,baseRiskWeight:92,minEntropy:4,signals:["OpenAI official secret prefix (sk-proj- or sk-)","High Shannon entropy key payload","Direct account credit exhaustion and model theft risk"],suggestedEnvName:()=>"OPENAI_API_KEY",remediationInstructions:["Revoke key at https://platform.openai.com/api-keys.","Verify credit consumption in OpenAI usage dashboard.","Inject credentials using OPENAI_API_KEY environment variable."]},{id:"anthropic-api-key",name:"Anthropic Claude API Key",provider:"Anthropic",pattern:/\b(sk-ant-[A-Za-z0-9_-]{30,})\b/g,baseConfidence:98,baseRiskWeight:92,minEntropy:3.8,signals:["Anthropic official secret token signature (sk-ant-)","High entropy cryptographic token payload","Direct Claude model API billing access"],suggestedEnvName:()=>"ANTHROPIC_API_KEY",remediationInstructions:["Revoke the API key in Anthropic Console.","Generate replacement key with spend limit configured.","Inject via ANTHROPIC_API_KEY environment variable."]},{id:"huggingface-token",name:"Hugging Face Access Token",provider:"Hugging Face",pattern:/\b(hf_[A-Za-z0-9]{34})\b/g,baseConfidence:98,baseRiskWeight:88,minEntropy:3.8,signals:["Hugging Face user access token format (hf_ prefix + 34 chars)","Grants access to gated AI models, private repositories, and inference endpoints"],suggestedEnvName:()=>"HF_TOKEN",remediationInstructions:["Revoke token immediately at https://huggingface.co/settings/tokens.","Audit access logs for unauthorized model downloads.","Inject credentials using the HF_TOKEN environment variable."]},{id:"stripe-secret-key",name:"Stripe Secret Key",provider:"Stripe",pattern:/\b((?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,100})\b/g,baseConfidence:97,baseRiskWeight:96,signals:["Stripe signature prefix (sk_live / rk_live / sk_test)","Financial transaction and customer credit card access","High financial liability and compliance breach"],suggestedEnvName:()=>"STRIPE_SECRET_KEY",remediationInstructions:["Roll API key immediately in Stripe Dashboard > Developers > API keys.","Audit recent transactions and payout bank account modifications.","Never bundle Stripe secret keys in frontend or mobile client builds."]},{id:"slack-bot-token",name:"Slack OAuth / Bot Token",provider:"Slack",pattern:/\b(xox[baprs]-[0-9A-Za-z-]{10,72})\b/g,baseConfidence:95,baseRiskWeight:82,signals:["Slack OAuth bot/user prefix (xoxb/xoxp/xoxa)","Internal company communications and workspace access"],suggestedEnvName:()=>"SLACK_BOT_TOKEN",remediationInstructions:["Revoke token in api.slack.com/apps.","Re-install app with minimal necessary OAuth scopes."]},{id:"slack-webhook",name:"Slack Incoming Webhook URL",provider:"Slack",pattern:/(https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9_]{8,12}\/B[A-Z0-9_]{8,12}\/[A-Za-z0-9_]{24})/g,baseConfidence:98,baseRiskWeight:78,signals:["Slack Incoming Webhook URL structure","Enables unauthorized message spoofing and channel phishing"],suggestedEnvName:()=>"SLACK_WEBHOOK_URL",remediationInstructions:["Delete the exposed webhook URL in Slack App settings.","Generate a new webhook URL and store in SLACK_WEBHOOK_URL."]},{id:"azure-storage-key",name:"Azure Shared Storage Key",provider:"Microsoft Azure",pattern:/["']?(?:AccountKey|azure_secret|azure_key)["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{86,88}==)(?:["';,\s\r\n)]|$)/gi,baseConfidence:93,baseRiskWeight:90,minEntropy:4.2,signals:["Azure storage account key signature (86-88 chars base64 with == padding)","Full administrative access to Azure Blob/Queue/Table storage"],suggestedEnvName:()=>"AZURE_STORAGE_KEY",remediationInstructions:["Regenerate storage key in Azure Portal.","Adopt Azure Managed Identity or Microsoft Entra ID authentication instead."]},{id:"azure-ad-client-secret",name:"Azure Active Directory Client Secret",provider:"Microsoft Azure",pattern:/["']?(?:azure[_-]?(?:client|ad|app)?[_-]?secret|client[_-]?secret)\s*[:=]\s*["']?([a-zA-Z0-9_~.-]{34,44})["']?(?:[\s\r\n;,)]|$)/gi,baseConfidence:90,baseRiskWeight:90,minEntropy:3.8,signals:["Azure AD / Entra ID client secret assignment pattern","Application impersonation and tenant directory access"],suggestedEnvName:()=>"AZURE_CLIENT_SECRET",remediationInstructions:["Revoke and rotate the client secret in Azure App Registrations portal.","Migrate to Managed Identity or Federated Credentials where possible."]},{id:"discord-bot-token",name:"Discord Bot Token",provider:"Discord",pattern:/\b([M-Z][A-Za-z0-9]{23,27}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,38})\b/g,baseConfidence:98,baseRiskWeight:88,signals:["Official Discord bot token format (ID.HMAC.Signature)","Complete bot control, server membership manipulation, and message reading"],suggestedEnvName:()=>"DISCORD_BOT_TOKEN",remediationInstructions:["Reset token in Discord Developer Portal > Bot > Reset Token.","Store in DISCORD_BOT_TOKEN environment variable."]},{id:"telegram-bot-token",name:"Telegram Bot Token",provider:"Telegram",pattern:/\b([0-9]{8,10}:[a-zA-Z0-9_-]{35})\b/g,baseConfidence:96,baseRiskWeight:85,signals:["Telegram Bot API token format (Numeric ID : 35-character secret)","Direct control of Telegram bot communications and webhooks"],suggestedEnvName:()=>"TELEGRAM_BOT_TOKEN",remediationInstructions:["Revoke and reissue the token using Telegram @BotFather (/revoke).","Store in TELEGRAM_BOT_TOKEN environment variable."]},{id:"pypi-api-token",name:"PyPI API Token",provider:"PyPI",pattern:/\b(pypi-[A-Za-z0-9_-]{50,150})\b/g,baseConfidence:99,baseRiskWeight:92,signals:["Official PyPI package index upload token prefix (pypi-)","Supply chain compromise and malicious Python package publication risk"],suggestedEnvName:()=>"PYPI_TOKEN",remediationInstructions:["Revoke the token immediately at https://pypi.org/manage/account/tokens/.","Inspect published package versions for tampering."]},{id:"shopify-access-token",name:"Shopify Admin / Storefront Access Token",provider:"Shopify",pattern:/\b(shp(?:at|ca|pa)_[a-fA-F0-9]{32})\b/g,baseConfidence:98,baseRiskWeight:92,signals:["Official Shopify access token prefix (shpat_, shpca_, shppa_)","E-commerce store data, customer orders, and payment configuration access"],suggestedEnvName:()=>"SHOPIFY_API_KEY",remediationInstructions:["Revoke the token in Shopify Admin > Apps and sales channels.","Audit store access and customer data logs."]},{id:"digitalocean-pat",name:"DigitalOcean Personal Access Token",provider:"DigitalOcean",pattern:/\b(dop_v1_[a-f0-9]{64})\b/g,baseConfidence:99,baseRiskWeight:92,signals:["Official DigitalOcean v1 token format (dop_v1_ prefix + 64 hex characters)","Droplet creation, destruction, and Cloud infrastructure control"],suggestedEnvName:()=>"DIGITALOCEAN_TOKEN",remediationInstructions:["Revoke the token in DigitalOcean Control Panel > API > Tokens.","Check active Droplets and firewall configurations for unauthorized changes."]},{id:"mailgun-api-key",name:"Mailgun Private API Key",provider:"Mailgun",pattern:/\b(key-[0-9a-zA-Z]{32})\b/g,baseConfidence:96,baseRiskWeight:85,signals:["Mailgun standard private API key signature (key- + 32 chars)","Bulk email dispatch and communication channel spoofing"],suggestedEnvName:()=>"MAILGUN_API_KEY",remediationInstructions:["Rotate key in Mailgun Dashboard > API Security.","Store in MAILGUN_API_KEY environment variable."]},{id:"square-access-token",name:"Square Access Token",provider:"Square",pattern:/\b(sq0atp-[0-9A-Za-z_-]{22}|sq0csp-[0-9A-Za-z_-]{43}|EAAA[a-zA-Z0-9_-]{60})\b/g,baseConfidence:97,baseRiskWeight:94,signals:["Square OAuth / production access token prefix (sq0atp-, sq0csp-, EAAA)","Payment processing, merchant account, and customer financial data access"],suggestedEnvName:()=>"SQUARE_ACCESS_TOKEN",remediationInstructions:["Revoke token in Square Developer Dashboard > OAuth settings.","Audit payment ledger and API access history."]},{id:"private-key",name:"Cryptographic Private Key (PEM)",provider:"Cryptography",pattern:/(-----BEGIN (?:[A-Z0-9_-]+ )*PRIVATE KEY(?: BLOCK)?-----(?:(?!-----BEGIN)[\s\S]){1,8192}?-----END (?:[A-Z0-9_-]+ )*PRIVATE KEY(?: BLOCK)?-----)/g,baseConfidence:100,baseRiskWeight:100,signals:["Standard PEM container header and footer","Unencrypted cryptographic private key","Total server impersonation, SSH compromise, or TLS decryption risk"],suggestedEnvName:()=>"PRIVATE_KEY_PATH",remediationInstructions:["Immediately decommission this private key pair.","Remove public key counterpart from all servers authorized_keys.","Never commit private keys to version control; use SSH agents or secret vaults."]},{id:"database-url",name:"Database Connection String with Credentials",provider:"Database",pattern:/\b((?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis):\/\/[^:\s'"@]+:([^@\s'"]+)@([a-zA-Z0-9_.-]+(?::[0-9]+)?(?:\/[^\s'"`;]*)?))/gi,baseConfidence:92,baseRiskWeight:88,minEntropy:3.2,signals:["Database connection URL containing embedded user:password credentials","Direct data exfiltration, deletion, or ransomware risk"],suggestedEnvName:()=>"DATABASE_URL",remediationInstructions:["Rotate the database user password immediately on the database server.","Migrate connection string to DATABASE_URL environment variable.","Enable SSL/TLS requirement and VPC network access controls."]},{id:"url-credentials",name:"URL with Embedded Credentials",provider:"Generic Credential",pattern:/\b(https?:\/\/[^:\s'"\/?#@]+:([^@\s'"\/?#]+)@([a-zA-Z0-9_.-]+(?::[0-9]+)?(?:\/[^\s'"`;]*)?))/gi,baseConfidence:90,baseRiskWeight:85,minEntropy:3,signals:["HTTP/HTTPS URL containing embedded user:password or user:token credentials","Authentication credential transmission in URL plain text"],suggestedEnvName:()=>"API_ENDPOINT_URL",remediationInstructions:["Remove credentials from URL; pass authentication in Authorization headers.","Rotate exposed password or access token immediately."]},{id:"bearer-token",name:"Authorization Bearer Token",provider:"Auth / Identity",pattern:/(?:Authorization|auth)\s*[:=]\s*["']?Bearer\s+([A-Za-z0-9_.~+/-]{20,255})["']?/gi,baseConfidence:92,baseRiskWeight:85,minEntropy:3.5,signals:["HTTP Authorization header with static Bearer token literal","API session impersonation and service authentication bypass"],suggestedEnvName:()=>"AUTH_TOKEN",remediationInstructions:["Revoke the exposed bearer token.","Inject bearer tokens dynamically from environment variables."]},{id:"jwt-token",name:"JSON Web Token (JWT)",provider:"Auth / Identity",pattern:/\b(ey[A-Za-z0-9_-]{15,}\.ey[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{10,})\b/g,baseConfidence:88,baseRiskWeight:75,minEntropy:4.1,signals:["Header.Payload.Signature Base64 tripartite JWT structure","Authentication session hijacking and privilege escalation"],suggestedEnvName:t=>t?.toUpperCase()||"AUTH_TOKEN",remediationInstructions:["Invalidate active sessions / revoke refresh token family in identity provider.","Never hardcode tokens in client or backend source repositories."]},{id:"gitlab-pat",name:"GitLab Personal Access Token",provider:"GitLab",pattern:/\b(glpat-[0-9a-zA-Z_-]{20,40})\b/g,baseConfidence:98,baseRiskWeight:90,signals:["GitLab personal access token prefix (glpat-)","Repository read/write and CI/CD control"],suggestedEnvName:()=>"GITLAB_TOKEN",remediationInstructions:["Revoke token in GitLab User Settings > Access Tokens.","Store in GITLAB_TOKEN environment variable."]},{id:"npm-access-token",name:"npm Access Token",provider:"npm",pattern:/\b(npm_[A-Za-z0-9]{36})\b/g,baseConfidence:99,baseRiskWeight:92,signals:["npm official access token prefix (npm_)","Package publication and account takeover capability"],suggestedEnvName:()=>"NPM_TOKEN",remediationInstructions:["Revoke token immediately at https://www.npmjs.com/settings/tokens.","Store in NPM_TOKEN environment variable."]},{id:"sendgrid-api-key",name:"SendGrid API Key",provider:"SendGrid",pattern:/\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b/g,baseConfidence:99,baseRiskWeight:85,signals:["SendGrid standard tripartite API key (SG.<22>.<43>)","Email spoofing and communication channel hijacking risk"],suggestedEnvName:()=>"SENDGRID_API_KEY",remediationInstructions:["Revoke key in SendGrid dashboard Settings > API Keys.","Store in SENDGRID_API_KEY environment variable."]},{id:"twilio-api-key",name:"Twilio Auth Token / API Secret",provider:"Twilio",pattern:/\b(SK[0-9a-fA-F]{32})\b|["']?(?:twilio[a-z0-9_-]*(?:auth_?token|api_?secret|secret)|(?:auth_?token|api_?secret))\s*[:=]\s*["']?([0-9a-fA-F]{32})["']?(?:[\s\r\n;,)]|$)/gi,baseConfidence:95,baseRiskWeight:90,minEntropy:3.5,signals:["Twilio Auth Token, API Key SID (SK...), or API Secret assignment","32-character hexadecimal secret token","Telephony API and SMS billing access"],suggestedEnvName:()=>"TWILIO_AUTH_TOKEN",remediationInstructions:["Rotate token in Twilio Console.","Store in TWILIO_AUTH_TOKEN environment variable."]},{id:"password-assignment",name:"Password in Source Code",provider:"Generic Credential",pattern:/["']?(?:password|passwd|pwd|db_password|db_pass)["']?\s*[:=]\s*["']?(?!(?:password|passwordRequired|required|required_field|true|false|null|undefined|string|default|changeme|placeholder|example|admin|test)\b)([^"'\r\n\s#;,]{8,64})["']?/gi,baseConfidence:82,baseRiskWeight:80,minEntropy:2.8,signals:["Hard-coded password assignment in code, .env, or YAML","Credential exposure in plain text"],suggestedEnvName:()=>"PASSWORD",remediationInstructions:["Rotate password immediately.","Store password in an environment variable or secrets manager.","Never commit plain passwords to version control."]},{id:"generic-api-key",name:"Generic API Secret Assignment",provider:"Generic Credential",pattern:/["']?(?:api_?key|secret_?key|auth_?token|client_?secret|access_?token|private_?key|jwt_?secret)["']?\s*[:=]\s*["']?(?!(?:process\.env|import\.meta\.env|os\.environ|ENV)\b)([A-Za-z0-9_.~/+=]{20,90})["']?(?:[\s\r\n;,)]|$)/gi,baseConfidence:80,baseRiskWeight:70,minEntropy:3.5,signals:["Sensitive identifier keyword assignment in code, .env, or YAML","High Shannon entropy string literal"],suggestedEnvName:t=>t?t.toUpperCase():"API_KEY",remediationInstructions:["Identify corresponding API provider and rotate credential.","Migrate credential to local .env file (ensure .env is in .gitignore)."]}];var Y=L(require("path")),on=[/api[_-]?key/i,/secret[_-]?key/i,/access[_-]?token/i,/auth[_-]?token/i,/private[_-]?key/i,/client[_-]?secret/i,/password/i,/credential/i,/session[_-]?token/i,/bearer/i,/aws[_-]?(?:access|secret)/i,/stripe[_-]?(?:secret|key)/i,/github[_-]?(?:token|pat)/i,/slack[_-]?token/i,/db[_-]?pass(?:word)?/i],rn=[/placeholder/i,/mock/i,/dummy/i,/fake/i,/sample/i,/test[_-]?(?:key|token|id)/i,/demo/i,/insert[_-]?here/i];function an(t,e){if(e){let n=Y.relative(e,t);if(!n.startsWith("..")&&!Y.isAbsolute(n))return n.replace(/\\/g,"/")}return Y.isAbsolute(t)?Y.basename(t):t.replace(/\\/g,"/")}function pt(t,e){let n=an(t,e).toLowerCase(),i=Y.basename(t).toLowerCase(),o=Y.extname(t).toLowerCase(),s=/(?:^|\/)(?:tests?|specs?|__tests__|__mocks__|fixtures|mocks)\//i.test(n)||/[._-](?:test|spec)\.[a-z0-9]+$/i.test(i)||/^(?:test|spec)\.[a-z0-9]+$/i.test(i),r=/(?:^|\/)(?:docs|doc|documentation|tutorials|guides)\/|readme\.md|contributing\.md|changelog\.md/i.test(n),a=/(?:^|\/)(?:example|sample|\.example|\.sample)/i.test(n)||/[._-](?:example|sample)\.[a-z0-9]+$/i.test(i),c=/^\.env(?:\.[a-z0-9]+)?$/.test(i)||/(?:^|\/)(?:config|settings|k8s|helm|deploy|tfvars)\//i.test(n)||/(?:^|[._-])(?:config|settings|secret|credential|database|deploy)\.[a-z0-9]+$/i.test(i)||[".env",".yaml",".yml",".json",".toml",".ini",".tf"].includes(o),l=/^\.env/.test(i)||/(?:secret|credential|id_rsa|private_key|keypair|auth_config)/i.test(i);return{fileExtension:o,isConfig:c,isTest:s,isDoc:r,isSensitiveName:l,isExampleOrSample:a}}function We(t,e){let n=t[e]||"",i=[];for(let m=Math.max(0,e-3);m<e;m++)i.push(t[m]);let o=[];for(let m=e+1;m<Math.min(t.length,e+4);m++)o.push(t[m]);let s,r=n.match(/(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*[:=]/),a=n.match(/["']?([a-zA-Z0-9_$-]+)["']?\s*[:=]/);r?s=r[1]:a&&(s=a[1]);let c=s?on.some(m=>m.test(s)):!1,l=s?rn.some(m=>m.test(s)):!1,u=/[:=]/.test(n),d=/(?:process\.env|os\.environ|dotenv|config|getenv)/i.test(n),p=/(?:authorization|bearer|x-api-key)/i.test(n),v=/^\s*(?:\/\/|#|\/\*|\*|--)/.test(n);return{inferredVariable:s,isSensitiveIdentifier:c,isBenignIdentifier:l,isAssignment:u,isEnvOrConfigAccess:d,isHeaderOrBearer:p,isInComment:v,surroundingBefore:i,matchedLine:n,surroundingAfter:o}}var ze=L(require("fs")),Ge=L(require("path")),_e=/(?:api_?key|secret|token|password|auth|credential|access_?key|private_?key)/i,ut=/(?:console\.(?:log|warn|error|info|debug)|logger\.|print\(|logging\.)/i,ie=null;function Ve(){if(ie)return ie;try{let t=Ge.join(__dirname,"ast-parser.js");if(ze.existsSync(t))return ie=require(t),ie}catch{}try{let t=Ge.join(__dirname,"../../dist/ast-parser.js");if(ze.existsSync(t))return ie=require(t),ie}catch{}try{return ie=require("typescript"),ie}catch{}return null}function ve(t,e){let n=Ve();if(!n||!(!e||/\.[jt]sx?$|\.m[jt]s$|\.c[jt]s$/i.test(e)))return null;try{return n.createSourceFile(e||"eval_target.tsx",t,n.ScriptTarget.Latest,!0,n.ScriptKind.TSX)}catch{return null}}function Ue(t,e,n,i,o){let s=t[e]||"";if(Ve()&&(!n||/\.[jt]sx?$|\.m[jt]s$|\.c[jt]s$/i.test(n)))if(i){let l=gt(i,o!==void 0?o:e);if(l)return l}else{let c,l;if(t.length>60){let d=Math.max(0,e-30),p=Math.min(t.length,e+30);c=t.slice(d,p).join(`
`),l=e-d}else c=t.join(`
`),l=e;let u=cn(c,l);if(u)return u}return dn(s)}function gt(t,e){try{let c=function(l){if(!a&&!(l.pos>r||l.end<s)&&(i.forEachChild(l,c),!a)){if(l.kind===i.SyntaxKind.BinaryExpression&&(l.operatorToken.kind===i.SyntaxKind.BarBarToken||l.operatorToken.kind===i.SyntaxKind.QuestionQuestionToken)){let u=l.left.getText(t);if(u.includes("process.env")||u.includes("env")||u.toLowerCase().includes("key")){a={variablePath:u,isSensitiveProperty:_e.test(u),isEnvFallback:!0,isAuthorizationHeader:!1,isLoggingCall:!1,scopeType:"ENV_FALLBACK"};return}}if(l.kind===i.SyntaxKind.PropertyAssignment){let u=l.name.getText(t),d=u,p=l.parent;for(;p;)p.kind===i.SyntaxKind.PropertyAssignment&&p.name?d=`${p.name.getText(t)}.${d}`:p.kind===i.SyntaxKind.VariableDeclaration&&p.name&&(d=`${p.name.getText(t)}.${d}`),p=p.parent;let v=_e.test(d),m=/authorization|bearer|x-api-key/i.test(u);a={variablePath:d,isSensitiveProperty:v,isEnvFallback:!1,isAuthorizationHeader:m,isLoggingCall:!1,scopeType:m?"HEADER":"OBJECT_PROPERTY"};return}if(l.kind===i.SyntaxKind.CallExpression){let u=l.expression.getText(t);if(ut.test(u)){a={variablePath:u,isSensitiveProperty:!1,isEnvFallback:!1,isAuthorizationHeader:!1,isLoggingCall:!0,scopeType:"FUNCTION_ARG"};return}}if(l.kind===i.SyntaxKind.VariableDeclaration){let u=l.name.getText(t);a={variablePath:u,isSensitiveProperty:_e.test(u),isEnvFallback:!1,isAuthorizationHeader:!1,isLoggingCall:!1,scopeType:"VARIABLE_DECLARATION"};return}}};var n=c;let i=Ve();if(!i)return null;let o=t.getLineStarts();if(e>=o.length)return null;let s=o[e],r=e+1<o.length?o[e+1]-1:t.text?.length||0,a=null;return c(t),a}catch{return null}}function cn(t,e){let n=ve(t);return n?gt(n,e):null}function dn(t){let e=ut.test(t),n=/(?:process\.env\.[A-Za-z0-9_]+|os\.(?:getenv|environ\.get)\([^)]+\))\s*(?:\|\||\?\?)\s*["'][^"']+["']/.test(t),i=/(?:authorization|x-api-key|bearer)\s*[:=]/i.test(t),o=t.match(/([a-zA-Z0-9_$.]+)\s*[:=]\s*["'][^"']+["']/)||t.match(/["']([a-zA-Z0-9_.]+)["']\s*:\s*["'][^"']+["']/),s,r=!1;o&&(s=o[1],r=_e.test(s));let a="UNKNOWN";return n?a="ENV_FALLBACK":i?a="HEADER":s&&s.includes(".")?a="OBJECT_PROPERTY":s?a="VARIABLE_DECLARATION":e&&(a="FUNCTION_ARG"),{variablePath:s,isSensitiveProperty:r,isEnvFallback:n,isAuthorizationHeader:i,isLoggingCall:e,scopeType:a}}function be(t){if(!t||t.length===0)return 0;let e={};for(let o of t)e[o]=(e[o]||0)+1;let n=0,i=t.length;for(let o in e){let s=e[o]/i;n-=s*Math.log2(s)}return Math.round(n*100)/100}function je(t){return/^[0-9a-fA-F]+$/.test(t)?{setName:"HEX",baseSize:16}:/^[A-Za-z0-9+/=_-]+$/.test(t)?{setName:"BASE64",baseSize:64}:/^[A-Za-z0-9]+$/.test(t)?{setName:"ALPHANUMERIC",baseSize:62}:/^[\x20-\x7E]+$/.test(t)?{setName:"ASCII_PRINTABLE",baseSize:95}:{setName:"SPECIAL",baseSize:128}}function ft(t){if(!t||t.length===0)return 0;let e=be(t),{baseSize:n}=je(t),i=Math.log2(n);if(i<=0)return 0;let o=Math.min(1,e/i);return Math.round(o*100)/100}var ln=[/\bplaceholder\b/i,/\byour[_-]?(?:api)?[_-]?key\b/i,/\byour[_-]?secret\b/i,/\byour[_-]?token\b/i,/\binsert[_-]?here\b/i,/\breplace[_-]?me\b/i,/\benter[_-]?your\b/i,/\bchange[_-]?me\b/i,/\bdummy\b/i,/\bfake[_-]?token\b/i,/xxxx+/i,/\btest[_-]?value\b/i,/AKIAIOSFODNN7EXAMPLE/i,/wJalrXUtnFEMI\/K7MDENG\/bPxRfiCYEXAMPLEKEY/i,/^123456789[0-9]*$/,/^abcdef[a-z0-9]*$/i,/00000000[0-9]*/,/sk_live_example/i,/ghp_example/i,/:\/\/[^:]+:(?:password|secret|changeme|pass|admin|test|postgres|root)@(?:localhost|127\.0\.0\.1)(?::\d+)?\b/i,/:\/\/(?:postgres|root):(postgres|root)@(?:localhost|127\.0\.0\.1)(?::\d+)?\b/i],pn=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,un=/^(?:mock|dummy|placeholder|fake|sample)_(?:key|token|secret|password|pwd|cred)$/i;function mt(t,e,n,i="Generic Credential"){let o=i.startsWith("Generic");if(/(?:process\.env|import\.meta\.env|os\.environ|ENV[\[\.])/.test(t))return{isFalsePositive:!0,reason:"Environment variable lookup expression, not a hard-coded credential literal",confidencePenalty:100};let s=/^(?:this|self|window|global|req|request|headers|config|options|ctx|context|env|process)\.[a-zA-Z0-9_$.]+/i.test(t)||/^[a-zA-Z_$][a-zA-Z0-9_$]*(?:\.[a-zA-Z_$][a-zA-Z0-9_$]*)+$/.test(t)&&!t.startsWith("ey")&&!t.startsWith("ya29.");if(o&&s)return{isFalsePositive:!0,reason:"Property access or object path expression, not a hard-coded credential literal",confidencePenalty:100};if(/^(?:passwordRequired|required_field|required|optional|placeholder|changeme|default|test|dummy|example|string|undefined|null)$/i.test(t))return{isFalsePositive:!0,reason:"Common non-secret schema or form attribute value",confidencePenalty:100};for(let a of ln)if(a.test(t))return{isFalsePositive:!0,reason:`Matched known documentation/placeholder pattern: ${a.source}`,confidencePenalty:100};if(e&&un.test(e)&&!(t.startsWith("AKIA")||t.startsWith("ASIA")||t.startsWith("ghp_")||t.startsWith("gho_")||t.startsWith("ghu_")||t.startsWith("ghs_")||t.startsWith("ghr_")||t.startsWith("github_pat_")||t.startsWith("glpat-")||t.startsWith("sk_live_")||t.startsWith("rk_live_")||t.startsWith("xoxb-")||t.startsWith("xoxp-")||t.startsWith("xoxa-")||t.startsWith("xoxr-")||t.startsWith("pypi-")||t.startsWith("dop_v1_")||t.startsWith("shpat_")||t.startsWith("shpca_")||t.startsWith("shppa_")||t.startsWith("ya29.")||t.startsWith("key-")||t.startsWith("sq0atp-")||t.startsWith("sq0csp-")||/^SK[0-9a-fA-F]{32}$/.test(t)||t.includes("-----BEGIN")||t.length>=14&&be(t)>=3.6))return{isFalsePositive:!0,reason:`Variable identifier indicates placeholder: ${e}`,confidencePenalty:100};let r=new Set(t.split("")).size;if(t.length>=10&&r<=3)return{isFalsePositive:!0,reason:"Low character diversity (repetitive filler characters)",confidencePenalty:95};if(pn.test(t)&&!e?.match(/secret|token|api_?key/i))return{isFalsePositive:!0,reason:"Standard UUID identifier without credential context",confidencePenalty:90};if(n){let a=/(?:docs|documentation|tutorials|guides)\/|readme\.md/i.test(n);if(/(?:example|sample|\.example|\.sample)/i.test(n)&&/example|your_/i.test(t))return{isFalsePositive:!0,reason:"Sample configuration value inside template/example file",confidencePenalty:90};if(a&&!t.startsWith("ghp_")&&!t.startsWith("AKIA"))return{isFalsePositive:!1,confidencePenalty:25}}return{isFalsePositive:!1,confidencePenalty:0}}function ht(t){if(!/^(AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}$/.test(t))return{isValid:!1,confidenceBonus:0,reason:"Invalid AWS key length or character set"};let e=t.substring(0,4);return{isValid:!0,confidenceBonus:10,reason:{AKIA:"Standard permanent IAM user access key",ASIA:"Temporary STS session access key",ABIA:"AWS Backup access key",ACCA:"AWS CodeCommit access key"}[e]||"Valid AWS Access Key ID structure"}}function vt(t){let e=/^sk_live_[0-9a-zA-Z]{24,100}$/.test(t)||/^rk_live_[0-9a-zA-Z]{24,100}$/.test(t),n=/^sk_test_[0-9a-zA-Z]{24,100}$/.test(t)||/^rk_test_[0-9a-zA-Z]{24,100}$/.test(t);return!e&&!n?{isValid:!1,confidenceBonus:0,reason:"Does not match official Stripe secret key format"}:{isValid:!0,confidenceBonus:e?12:5,reason:e?"Production live Stripe Secret Key":"Stripe Test API key"}}function bt(t){return/^ghp_[A-Za-z0-9_]{36}$/.test(t)?{isValid:!0,confidenceBonus:12,reason:"GitHub Personal Access Token (Classic)"}:/^gho_[A-Za-z0-9_]{36}$/.test(t)?{isValid:!0,confidenceBonus:10,reason:"GitHub OAuth Access Token"}:/^ghs_[A-Za-z0-9_]{36}$/.test(t)?{isValid:!0,confidenceBonus:10,reason:"GitHub Server-to-server token"}:/^github_pat_[A-Za-z0-9_]{82}$/.test(t)?{isValid:!0,confidenceBonus:15,reason:"GitHub Fine-Grained Personal Access Token"}:{isValid:!1,confidenceBonus:0,reason:"Invalid GitHub token prefix or length"}}function yt(t){let e=t.split(".");if(e.length!==3)return{isValid:!1,confidenceBonus:0,reason:"Not a 3-part dot-separated JWT"};try{let n=Buffer.from(e[0],"base64url").toString("utf8"),i=JSON.parse(n);if(i&&typeof i=="object"&&i.alg)return{isValid:!0,confidenceBonus:15,reason:`Valid JWT structure with signature algorithm: ${i.alg}`}}catch{}return{isValid:!1,confidenceBonus:0,reason:"Malformed JWT header JSON payload"}}function kt(t){try{let e=new URL(t);if(!["postgres:","postgresql:","mysql:","mongodb:","mongodb+srv:","redis:"].includes(e.protocol))return{isValid:!1,confidenceBonus:0,reason:"Unsupported database protocol scheme"};if(e.password&&e.password.length>0)return{isValid:!0,confidenceBonus:12,reason:`Database connection string containing credentials for user '${e.username||"default"}'`}}catch{let e=/^(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis):\/\/[^:\s'"]+:([^\s'"]+)@([a-zA-Z0-9_.-]+(?::[0-9]+)?\/[^\s'"`;]*)/i,n=t.match(e);if(n&&n[1])return{isValid:!0,confidenceBonus:10,reason:"Database connection URI structure matched with embedded password"}}return{isValid:!1,confidenceBonus:0,reason:"Invalid database connection URL structure"}}function St(t){return/^sk-proj-[A-Za-z0-9_-]{48,}$/.test(t)?{isValid:!0,confidenceBonus:15,reason:"Valid OpenAI Project API Key format"}:/^sk-admin-[A-Za-z0-9_-]{48,}$/.test(t)?{isValid:!0,confidenceBonus:15,reason:"Valid OpenAI Admin/Organization API Key format"}:/^sk-svcacct-[A-Za-z0-9_-]{48,}$/.test(t)?{isValid:!0,confidenceBonus:15,reason:"Valid OpenAI Service Account Key format"}:/^sk-[A-Za-z0-9]{32,48}$/.test(t)?{isValid:!0,confidenceBonus:10,reason:"Valid OpenAI Standard/Legacy API Key format"}:{isValid:!1,confidenceBonus:0,reason:"Invalid OpenAI API key structure"}}function At(t){return/^sk-ant-[A-Za-z0-9_-]{40,}$/.test(t)?{isValid:!0,confidenceBonus:15,reason:"Valid Anthropic Claude API Key format"}:{isValid:!1,confidenceBonus:0,reason:"Invalid Anthropic API key format"}}function Et(t){return/^AIza[0-9A-Za-z_-]{35}$/.test(t)?{isValid:!0,confidenceBonus:12,reason:"Valid Google Cloud / Gemini AIza service key signature"}:{isValid:!1,confidenceBonus:0,reason:"Invalid Google Cloud API key format"}}function xt(t){return/^xox[baprs]-[0-9A-Za-z-]{10,72}$/.test(t)?{isValid:!0,confidenceBonus:12,reason:`Valid Slack ${t.startsWith("xoxb")?"Bot Token":t.startsWith("xoxp")?"User Token":"OAuth Token"} signature`}:{isValid:!1,confidenceBonus:0,reason:"Invalid Slack token structure"}}function It(t){return/^hf_[A-Za-z0-9]{34}$/.test(t)?{isValid:!0,confidenceBonus:12,reason:"Valid Hugging Face User Access Token format"}:{isValid:!1,confidenceBonus:0,reason:"Invalid Hugging Face token structure"}}function Ct(t){return/^[A-Za-z0-9/+=]{40}$/.test(t)?{isValid:!0,confidenceBonus:12,reason:"Valid 40-character AWS Secret Access Key Base64 format"}:{isValid:!1,confidenceBonus:0,reason:"Invalid AWS Secret Access Key format"}}function wt(t){return/^https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9_]{8,12}\/B[A-Z0-9_]{8,12}\/[A-Za-z0-9_]{24}$/.test(t)?{isValid:!0,confidenceBonus:15,reason:"Valid Slack Incoming Webhook URL structure"}:{isValid:!1,confidenceBonus:0,reason:"Invalid Slack Incoming Webhook URL"}}function _t(t){return/^[A-Za-z0-9/+=]{86,88}==$/.test(t)?{isValid:!0,confidenceBonus:12,reason:"Valid Azure Storage Account Key Base64 format with padding"}:{isValid:!1,confidenceBonus:0,reason:"Invalid Azure Storage Key format"}}function Rt(t){let e=/-----BEGIN (?:[A-Z0-9_-]+ )*PRIVATE KEY(?: BLOCK)?-----/.test(t),n=/-----END (?:[A-Z0-9_-]+ )*PRIVATE KEY(?: BLOCK)?-----/.test(t);return e&&n?{isValid:!0,confidenceBonus:20,reason:"Valid Cryptographic Private Key PEM block container"}:{isValid:!1,confidenceBonus:0,reason:"Incomplete or malformed PEM key container"}}function Ze(t,e,n,i,o,s){let r=[],a=t.baseConfidence;r.push({signal:"KNOWN_PATTERN_MATCH",description:`Matched recognized credential signature for ${t.provider} (${t.name})`,confidenceImpact:0,details:{ruleId:t.id,provider:t.provider}});let c=be(e),l=ft(e),{setName:u}=je(e);if(t.minEntropy&&c<t.minEntropy?(a=Math.max(10,a-30),r.push({signal:"LOW_ENTROPY",description:`Low entropy score: ${c} bits/char below minimum threshold of ${t.minEntropy}`,confidenceImpact:-30,details:{shannonEntropy:c,minEntropy:t.minEntropy}})):c>=4.5?(a=Math.min(100,a+5),r.push({signal:"HIGH_ENTROPY",description:`Cryptographic entropy: ${c} bits/char (${u} set), indicates non-human randomness`,confidenceImpact:5,details:{shannonEntropy:c,normalizedEntropy:l,characterSet:u}})):c>=3.4?r.push({signal:"MODERATE_ENTROPY",description:`Moderate entropy: ${c} bits/char (${u} set)`,confidenceImpact:0,details:{shannonEntropy:c,normalizedEntropy:l,characterSet:u}}):(a=Math.max(10,a-15),r.push({signal:"LOW_ENTROPY",description:`Low entropy score: ${c} bits/char (${u} set)`,confidenceImpact:-15,details:{shannonEntropy:c,normalizedEntropy:l,characterSet:u}})),i.isSensitiveIdentifier||s?.isSensitiveProperty){let S=s?.variablePath||i.inferredVariable||"credential";a=Math.min(100,a+10),r.push({signal:"SENSITIVE_IDENTIFIER",description:`Assigned to sensitive identifier / property: '${S}'`,confidenceImpact:10,details:{identifier:S}})}else i.isBenignIdentifier&&(a=Math.max(10,a-25),r.push({signal:"BENIGN_IDENTIFIER",description:`Identifier name indicates mock or sample value: '${i.inferredVariable}'`,confidenceImpact:-25,details:{identifier:i.inferredVariable}}));s?.isEnvFallback&&(a=Math.min(100,a+12),r.push({signal:"ENV_FALLBACK_ASSIGNMENT",description:'Hardcoded literal provided as environment variable fallback (e.g. process.env.KEY || "...")',confidenceImpact:12})),s?.isAuthorizationHeader&&(a=Math.min(100,a+10),r.push({signal:"AUTHORIZATION_HEADER",description:"Passed in HTTP Authorization or Bearer token header context",confidenceImpact:10})),(n.isConfig||n.isSensitiveName)&&(a=Math.min(100,a+8),r.push({signal:"PRODUCTION_CONFIG_FILE",description:`Located in configuration or secret storage file (${n.fileExtension})`,confidenceImpact:8,details:{isConfig:n.isConfig,extension:n.fileExtension}})),n.isTest&&(a=Math.max(20,a-20),r.push({signal:"TEST_FILE_PENALTY",description:"Found inside test/mock directory structure",confidenceImpact:-20})),n.isDoc&&(a=Math.max(20,a-25),r.push({signal:"DOCUMENTATION_PENALTY",description:"Found inside documentation or markdown guide",confidenceImpact:-25}));let d;t.id==="aws-access-key"?d=ht(e):t.id==="aws-secret-key"?d=Ct(e):t.id==="stripe-secret-key"?d=vt(e):t.id==="github-pat"?d=bt(e):t.id==="jwt-token"?d=yt(e):t.id==="database-url"?d=kt(e):t.id==="openai-api-key"?d=St(e):t.id==="anthropic-api-key"?d=At(e):t.id==="google-api-key"?d=Et(e):t.id==="slack-bot-token"?d=xt(e):t.id==="slack-webhook"?d=wt(e):t.id==="azure-storage-key"?d=_t(e):t.id==="huggingface-token"?d=It(e):t.id==="private-key"&&(d=Rt(e)),d&&d.isValid&&(a=Math.min(100,a+d.confidenceBonus),r.push({signal:"STRUCTURAL_VALIDATION_PASSED",description:`Structural validation verified: ${d.reason}`,confidenceImpact:d.confidenceBonus}));let p=mt(e,i.inferredVariable,o,t.provider);if(p.isFalsePositive)return{confidence:0,evidence:{items:[{signal:"KNOWN_PLACEHOLDER_REJECTED",description:p.reason||"Placeholder value rejected",confidenceImpact:-100}],shannonEntropy:c,normalizedEntropy:l,characterSet:u,surroundingCode:{before:i.surroundingBefore,targetLine:i.matchedLine,after:i.surroundingAfter,inferredVariable:i.inferredVariable},fileContext:{fileExtension:n.fileExtension,isConfig:n.isConfig,isTest:n.isTest,isDoc:n.isDoc,isSensitiveName:n.isSensitiveName,isExampleOrSample:n.isExampleOrSample}},isSuppressed:!0,suppressReason:p.reason};p.confidencePenalty>0&&(a=Math.max(10,a-p.confidencePenalty));let v=Math.max(0,Math.min(100,Math.round(a))),m={items:r,shannonEntropy:c,normalizedEntropy:l,characterSet:u,surroundingCode:{before:i.surroundingBefore,targetLine:i.matchedLine,after:i.surroundingAfter,inferredVariable:i.inferredVariable},fileContext:{fileExtension:n.fileExtension,isConfig:n.isConfig,isTest:n.isTest,isDoc:n.isDoc,isSensitiveName:n.isSensitiveName,isExampleOrSample:n.isExampleOrSample}};return{confidence:v,evidence:m,isSuppressed:!1}}function qe(t,e,n,i){let o=[],s=0,r=Math.min(40,Math.round(t.baseRiskWeight/100*40));s+=r,o.push({factor:"CREDENTIAL_SEVERITY",weight:40,scoreContribution:r,explanation:`${t.provider} ${t.name} has high inherent privilege capability`});let a=Math.round(e/100*25);s+=a,o.push({factor:"CONFIDENCE_LEVEL",weight:25,scoreContribution:a,explanation:`Multi-signal verification confidence is ${e}%`});let c=5,l="Standard source code file";n.isConfig||n.isSensitiveName?(c=15,l="Located in sensitive deployment / environment configuration"):n.isTest?(c=0,l="Located in test / fixture codebase with reduced operational blast radius"):n.isDoc&&(c=0,l="Located in documentation context"),s+=c,o.push({factor:"STORAGE_ENVIRONMENT",weight:15,scoreContribution:c,explanation:l});let u=5,d="Found in local uncommitted working tree";i&&(i.isRemote?(u=20,d="Pushed to remote repository branch (external exposure risk)"):i.isPresentInHistory?(u=16,d=`Committed to Git history across ${i.branches.length||1} branch(es) (${i.exposureDurationDays} days exposure)`):i.isPresentInHead&&(u=12,d="Committed in current HEAD commit")),s+=u,o.push({factor:"EXPOSURE_REACH",weight:20,scoreContribution:u,explanation:d});let p=Math.max(0,Math.min(100,Math.round(s))),v="LOW";p>=76?v="CRITICAL":p>=51?v="HIGH":p>=26?v="MEDIUM":v="LOW";let m=gn(p,i),S=`${v} Risk (${p}/100) \u2014 ${t.name}. ${m.summary}`;return{score:p,tier:v,factors:o,blastRadius:m,summary:S}}function gn(t,e){let n=[],i=Math.round(t*.5),o=e?e.isPresentInHead:!0,s=e?e.isPresentInHistory:!1,r=e?.isPresentInHistory?1:0,a=e?.branches||["main"],c=a.length,l=e?.isRemote||!1,u=e?.exposureDurationDays||0;o&&(n.push("Active working tree contains exposed secret"),i+=15),s&&(n.push(`Git history contains commit records across ${c} branch(es)`),i+=20),l&&(n.push("Secret has been synchronized to remote tracking branches"),i+=25),u>7&&(n.push(`Exposure duration exceeds ${u} days without rotation`),i+=10),i=Math.max(0,Math.min(100,i));let d="CONTAINED";i>=75?d="SEVERE":i>=50?d="EXTENSIVE":i>=25?d="MODERATE":d="CONTAINED";let p=`Blast Radius: ${d} (${i}/100) \u2014 ${l?"Remote & history exposure":s?"Historical commit exposure":"Contained to local working tree"}`;return{level:d,score:i,workingTreeExposed:o,gitHistoryExposed:s,commitCount:r,branchCount:c,branches:a,remoteExposed:l,exposureDurationDays:u,summary:p,factors:n}}var te=L(require("fs")),se=L(require("path"));var Tt=L(require("crypto")),Re=L(require("fs")),Pt=L(require("path")),fn="sld_fingerprint_salt_v1_d8e9f2a1b4c3e7f0";function mn(t,e){if(t)return t;if(process.env.SLD_SALT)return process.env.SLD_SALT;let n=e||process.cwd();try{let i=Pt.join(n,".sld","salt");if(Re.existsSync(i)){let o=Re.readFileSync(i,"utf8").trim();if(o)return o}}catch{}return fn}function ye(t){if(!t)return"";let e=t.length;if(e<=12)return"\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022";let n=Math.max(2,Math.floor(e*.2)),i=Math.min(4,Math.max(1,Math.floor(n/2))),o=Math.min(3,Math.max(1,n-i)),s=Math.max(6,Math.min(16,e-i-o)),r=t.substring(0,i),a=t.substring(e-o),c="\u2022".repeat(s);return`${r}${c}${a}`}function Ye(t,e,n){let i=mn(e,n);return Tt.createHmac("sha256",i).update(t).digest("hex").substring(0,16)}function Je(t){return t.replace(/\\/g,"\\\\").replace(/"/g,'\\"').replace(/\$/g,"\\$").replace(/\n/g,"\\n").replace(/\r/g,"\\r")}function Ot(t,e){switch(se.extname(t).toLowerCase()){case".py":return`os.environ.get("${e}")`;case".go":return`os.Getenv("${e}")`;case".rb":return`ENV['${e}']`;case".php":return`getenv('${e}')`;case".java":case".kt":return`System.getenv("${e}")`;case".rs":return`std::env::var("${e}").unwrap()`;case".sh":case".bash":case".zsh":return`"\${${e}}"`;case".yaml":case".yml":case".toml":case".env":return`\${${e}}`;case".js":case".jsx":case".ts":case".tsx":case".mjs":case".cjs":default:return`process.env.${e}`}}function Xe(t,e,n,i,o){let s=t.suggestedEnvName(o),r=Ot(n,s),a=ye(e),c=Je(e),l=[`1. Revoke / rotate credential immediately with provider: ${t.provider}`,`2. Migrate secret value to local .env file (${s})`,`3. Replace hardcoded literal in ${n} with ${r}`,"4. Verify .env is listed in .gitignore so it is never committed","5. If committed previously, purge from Git history using git-filter-repo or BFG","6. Rescan file and commit to verify exposure is eliminated"],u=`${s}="${c}"`,d=`${s}=your_${s.toLowerCase()}_here`,p=`# WARNING: Use BFG Repo Cleaner to purge secrets from history (safer than filter-repo --invert-paths):
#   java -jar bfg.jar --replace-text secrets.txt <repo-dir>
# Where secrets.txt lists the exact literal to redact (one per line).
# Then force-push: git push --force --all && git push --force --tags
# Alternatively with git-filter-repo (rewrites content, not paths):
#   git filter-repo --replace-text secrets.txt`,v=`--- a/${n}
+++ b/${n}
@@ -${i},1 +${i},1 @@
- ... "${a}" ...
+ ... ${r} ...`;return{steps:l,envVarName:s,replacementCode:r,envFileSnippet:u,envExampleSnippet:d,gitHistoryPurgeCommand:p,diffPreview:v}}function hn(t,e,n){let i=t.split(/\r?\n/),o=new Map;for(let s of i){let r=s.trim();if(!r||r.startsWith("#"))continue;let a=r.indexOf("=");if(a!==-1){let c=r.substring(0,a).trim(),l=r.substring(a+1).trim();(l.startsWith('"')&&l.endsWith('"')||l.startsWith("'")&&l.endsWith("'"))&&(l=l.substring(1,l.length-1)),o.set(c,l)}}if(o.has(e)){let s=o.get(e);if(s===Je(n)||s===n)return{varName:e,isReused:!0};let r=2;for(;o.has(`${e}_${r}`);){if(o.get(`${e}_${r}`)===n)return{varName:`${e}_${r}`,isReused:!0};r++}return{varName:`${e}_${r}`,isReused:!1}}return{varName:e,isReused:!1}}function vn(t){let e=se.join(t,".gitignore");if(te.existsSync(e)){let n=te.readFileSync(e,"utf8");if(!n.split(/\r?\n/).some(s=>/^\s*\.env(?:\s|$)/.test(s))){let s=n.endsWith(`
`)||n.length===0?"":`
`;te.appendFileSync(e,`${s}# Credentials
.env
.env.*.local
`,"utf8")}}else te.writeFileSync(e,`# Credentials
.env
.env.*.local
`,"utf8");try{let{execFileSync:n}=require("child_process");try{n("git",["rev-parse","--is-inside-work-tree"],{cwd:t,stdio:"ignore"})}catch{return}try{throw n("git",["ls-files","--error-unmatch",".env"],{cwd:t,stdio:"ignore"}),new Error('.env is already tracked in Git index. Run "git rm --cached .env" to untrack it before storing secrets.')}catch(i){if(i.message&&i.message.includes("already tracked in Git index"))throw i}try{n("git",["check-ignore","-q",".env"],{cwd:t,stdio:"ignore"})}catch{throw new Error(".env is not ignored by Git according to git check-ignore.")}}catch(n){if(n.message&&(n.message.includes("already tracked")||n.message.includes("not ignored by Git")))throw n}}function Ft(t,e,n=te){let i=t.fullPath,o=null,s=null,r=null,a=null,c=!1,l=!1,u=!1,d=se.join(e,".env"),p=se.join(e,".gitignore");try{if(!n.existsSync(i))return{success:!1,message:`Target file not found: ${i}`,envPath:"",modifiedFile:i};if(o=n.readFileSync(i,"utf8"),!o.includes(t.rawSecret))return{success:!1,message:"Secret no longer found in target file (may have already been modified).",envPath:"",modifiedFile:i};let v="";if(n.existsSync(d))s=n.readFileSync(d,"utf8"),v=s;else{c=!0;try{n.writeFileSync(d,"",{mode:384,encoding:"utf8"})}catch{}}n.existsSync(p)?r=n.readFileSync(p,"utf8"):l=!0;let m=t.remediation?.envVarName||"API_KEY",{varName:S,isReused:b}=hn(v,m,t.rawSecret),A=Ot(i,S),k=Je(t.rawSecret),P=`${S}="${k}"
`;if(vn(e),!b){let f=v.endsWith(`
`)||v.length===0?"":`
`;n.appendFileSync(d,`${f}${P}`,"utf8");try{n.chmodSync(d,384)}catch{}}let I=se.join(e,".env.example"),D=`${S}=your_${S.toLowerCase()}_here
`,g=n.existsSync(I);if(g?a=n.readFileSync(I,"utf8"):u=!0,!g||!n.readFileSync(I,"utf8").includes(S)){let f=g?n.readFileSync(I,"utf8"):"",x=f.endsWith(`
`)||f.length===0?"":`
`;n.appendFileSync(I,`${x}${D}`,"utf8")}let y=o,C=`"${t.rawSecret}"`,R=`'${t.rawSecret}'`,T=`\`${t.rawSecret}\``;return y.includes(C)?y=y.replace(new RegExp(Te(C),"g"),A):y.includes(R)?y=y.replace(new RegExp(Te(R),"g"),A):y.includes(T)?y=y.replace(new RegExp(Te(T),"g"),A):y=y.replace(new RegExp(Te(t.rawSecret),"g"),A),n.writeFileSync(i,y,"utf8"),{success:!0,message:`Successfully migrated ${t.type} to .env (${S}) and replaced in ${t.file}.`,envPath:d,modifiedFile:i}}catch(v){let m=[],S=(k,P)=>{let I=`${k}.sld-tmp-${Date.now()}`;n.writeFileSync(I,P,"utf8"),n.renameSync(I,k)};if(o!==null)try{S(i,o),n.readFileSync(i,"utf8")!==o&&m.push(`source file restored with mismatched content (${i})`)}catch(k){m.push(`source file restore failed (${i}): ${k.message}`)}if(c&&n.existsSync(d))try{n.unlinkSync(d),n.existsSync(d)&&m.push(".env delete did not take effect")}catch(k){m.push(`.env delete failed: ${k.message}`)}else if(s!==null&&n.existsSync(d))try{S(d,s)}catch(k){m.push(`.env restore failed: ${k.message}`)}if(l&&n.existsSync(p))try{n.unlinkSync(p),n.existsSync(p)&&m.push(".gitignore delete did not take effect")}catch(k){m.push(`.gitignore delete failed: ${k.message}`)}else if(r!==null&&n.existsSync(p))try{S(p,r)}catch(k){m.push(`.gitignore restore failed: ${k.message}`)}let b=se.join(e,".env.example");if(u&&n.existsSync(b))try{n.unlinkSync(b),n.existsSync(b)&&m.push(".env.example delete did not take effect")}catch(k){m.push(`.env.example delete failed: ${k.message}`)}else if(a!==null&&n.existsSync(b))try{S(b,a)}catch(k){m.push(`.env.example restore failed: ${k.message}`)}let A=m.length===0?"Rollback completed successfully.":`ROLLBACK INCOMPLETE \u2014 manual inspection required: ${m.join("; ")}`;return{success:!1,message:`Remediation failed: ${v.message}. ${A}`,envPath:"",modifiedFile:t.fullPath}}}function Te(t){return t.replace(/[.*+?^${}()|[\]\\]/g,"\\$&")}var Oe=L(require("zlib"));function Pe(t,e){let n="",i=t.length-t.length%4;for(let o=0;o<i;o+=4){let s=e?t.readUInt32LE(o):t.readUInt32BE(o);s!==0&&s<=1114111&&!(s>=55296&&s<=57343)&&(n+=String.fromCodePoint(s))}return n}function ce(t){if(t.length===0)return"";if(t.length>=2&&t[0]===31&&t[1]===139)try{let s=Oe.gunzipSync(t,{maxOutputLength:67108864,finishFlush:Oe.constants.Z_SYNC_FLUSH}),r=ce(s);if(r!==null)return r}catch{}if(t.length>=4){if(t[0]===255&&t[1]===254&&t[2]===0&&t[3]===0)return Pe(t.subarray(4),!0);if(t[0]===0&&t[1]===0&&t[2]===254&&t[3]===255)return Pe(t.subarray(4),!1)}if(t.length>=2&&t[0]===255&&t[1]===254)return t.subarray(2).toString("utf16le");if(t.length>=2&&t[0]===254&&t[1]===255){let s=Buffer.from(t.subarray(2));return s.swap16(),s.toString("utf16le")}if(t.length>=8){let s=Math.min(t.length-t.length%4,256),r=0,a=0;for(let l=0;l<s;l+=4)t[l+1]===0&&t[l+2]===0&&t[l+3]===0&&t[l]!==0&&r++,t[l]===0&&t[l+1]===0&&t[l+2]===0&&t[l+3]!==0&&a++;let c=s/4;if(r>c*.3)return Pe(t,!0);if(a>c*.3)return Pe(t,!1)}if(t.length>=4){let s=0,r=0,a=Math.min(t.length,512);for(let c=0;c<a;c++)t[c]===0&&(c%2===1?s++:r++);if(s>=2&&s>r*2&&s/(a/2)>.25)return t.toString("utf16le");if(r>=2&&r>s*2&&r/(a/2)>.25){let c=Buffer.from(t);return c.swap16(),c.toString("utf16le")}}let e=Math.min(t.length,8192),n=0;for(let s=0;s<e;s++){let r=t[s];(r>=0&&r<=8||r===11||r===12||r>=14&&r<=31)&&n++}if(n<=e*.2)return t.toString("utf8").replace(/\0/g," ");let o=t.toString("latin1").match(/[\x20-\x7E\t]{8,}/g);return o&&o.length>0?o.join(`
`):null}function Lt(t){return Dt.createHash("sha256").update(t.replace(/\\/g,"/")).digest("hex").slice(0,8)}function bn(t,e=4e3){let n=t.split(/\r?\n/),i=!1;for(let a=0;a<n.length;a++)if(n[a].length>e){i=!0;break}if(!i){let a=n.map((l,u)=>u+1),c=new Array(n.length).fill(0);return{text:t,origLine:a,colOffset:c}}let o=[],s=[],r=[];for(let a=0;a<n.length;a++){let c=n[a],l=a+1;if(c.length<=e)o.push(c),s.push(l),r.push(0);else for(let d=0;d<c.length&&(o.push(c.substring(d,d+e)),s.push(l),r.push(d),!(d+e>=c.length));d+=e-512);}return{text:o.join(`
`),origLine:s,colOffset:r}}function $t(t,e){return/(?:\/\/|#|\/\*|--)\s*(?:sld-ignore|secret-leak-ignore)/i.test(t)?!0:/^\s*(?:\/\/|#|\/\*|--)\s*(?:sld-ignore|secret-leak-ignore)(?:\s*\*\/)?\s*$/i.test(e)}function de(t,e,n={}){let i=typeof n=="string"?{workspaceRoot:n}:n,{text:o,origLine:s,colOffset:r}=bn(t),a=i.rules||lt,c=i.workspaceRoot,l=pt(e,c),u=t.split(/\r?\n/),d=[],p=!e||/\.[jt]sx?$|\.m[jt]s$|\.c[jt]s$/i.test(e),v=i.cachedSourceFile||(p?ve(t,e):null),m=null;function S(){if(!m){m=[0];for(let f=0;f<o.length;f++)o.charCodeAt(f)===10&&m.push(f+1)}return m}function b(f){let x=S(),w=0,M=x.length-1;for(;w<=M;){let W=w+M>>1;if(x[W]<=f){if(W===x.length-1||x[W+1]>f){let j=W,ne=f-x[W]+1,Q=s[j]!==void 0?s[j]:j+1,ue=(r[j]||0)+ne;return{line:Q,column:ue}}w=W+1}else M=W-1}let $=s[0]!==void 0?s[0]:1,H=(r[0]||0)+f+1;return{line:$,column:H}}function A(f){let x=f-1;if(u.length<=1e3)return{lines:u,relativeTargetIdx:x};let w=Math.max(0,x-30),M=Math.min(u.length-1,x+30);return{lines:u.slice(w,M+1),relativeTargetIdx:x-w}}for(let f of a){f.pattern.lastIndex=0;let x;for(;(x=f.pattern.exec(o))!==null;){let w=x[1]!==void 0?x[1]:x[0],M=x[1]!==void 0?x[0].indexOf(x[1]):0,$=x.index+(M>=0?M:0),{line:H,column:W}=b($),j=u[H-1]||"",ne=H>1?u[H-2]:"";if(!i?.disallowInlineIgnore&&$t(j,ne))continue;let Q=A(H),ue=We(Q.lines,Q.relativeTargetIdx),q=Ue(Q.lines,Q.relativeTargetIdx,e,v,H-1),U=Ze(f,w,l,ue,e,q);if(U.isSuppressed)continue;let ee;if(f.minEntropy!==void 0&&(f.id==="generic-api-key"&&i.minEntropyThreshold!==void 0?ee=i.minEntropyThreshold:ee=f.minEntropy),ee!==void 0&&U.evidence.shannonEntropy<ee)continue;let re=e;if(c){let he=ge.relative(c,e);!he.startsWith("..")&&!ge.isAbsolute(he)&&(re=he)}let me=qe(f,U.confidence,l),xe=Xe(f,w,re,H,ue.inferredVariable),Ie=Lt(re),Ce=Ye(w,void 0,c),He=`sec_${Ce}_${Ie}`,ae=ye(w),Yt={id:He,fingerprint:Ce,type:f.name,provider:f.provider,file:re,fullPath:e,line:H,column:W,length:w.length,rawSecret:w,redactedSecret:ae,confidence:U.confidence,risk:me.tier,riskAssessment:me,evidence:U.evidence,remediation:xe,status:"ACTIVE",detectedAt:new Date().toISOString(),signals:U.evidence.items.map(he=>he.description),exampleFix:xe.replacementCode,entropy:U.evidence.shannonEntropy};d.push(Yt)}}let k=[],P=/["']([^"'\r\n]{2,80})["']\s*\+\s*["']([^"'\r\n]{8,120})["']/g,I;for(;(I=P.exec(o))!==null;)k.push({combined:I[1]+I[2],matchOffset:I.index,matchLength:I[0].length,description:"Resolved split string concatenation"});let D=/\[([^\]\r\n]{4,300})\]\s*\.\s*join\s*\(\s*["']\s*["']\s*\)/g,g;for(;(g=D.exec(o))!==null;){let f=/["']([^"'\r\n]*)["']/g,x=[],w;for(;(w=f.exec(g[1]))!==null;)x.push(w[1]);x.length>=2&&k.push({combined:x.join(""),matchOffset:g.index,matchLength:g[0].length,description:"Resolved split array join expression"})}let y=/`([^`\r\n]{2,80})\$\{\s*["']([^"'\r\n]{8,120})["']\s*\}([^`\r\n]*?)`/g,C;for(;(C=y.exec(o))!==null;)k.push({combined:C[1]+C[2]+(C[3]||""),matchOffset:C.index,matchLength:C[0].length,description:"Resolved template literal interpolation"});let R=/(?:(?:Buffer\.from|atob|b64decode|b64_decode|base64_decode|DecodeString)\s*\(\s*(?:b)?["']([A-Za-z0-9+/=_-]{20,300})["']|["']([A-Za-z0-9+/_-]{20,}={0,2})["']|(?:=|\:)\s*([A-Za-z0-9+/_-]{20,}={0,2})|(?:^|[\r\n\s])([A-Za-z0-9+/_-]{24,}={0,2})(?:[\r\n\s]|$))/g,T;for(;(T=R.exec(o))!==null;){let f=T[1]||T[2]||T[3]||T[4];if(f)try{let x=f.replace(/-/g,"+").replace(/_/g,"/"),w=(4-x.length%4)%4,M=x+"=".repeat(w),$=Buffer.from(M,"base64").toString("utf8");$.length>=10&&/^[\x20-\x7E\r\n\t]+$/.test($)&&k.push({combined:$,matchOffset:T.index,matchLength:T[0].length,description:"Resolved base64-encoded credential payload"})}catch{}}for(let f of k)for(let x of a){x.pattern.lastIndex=0;let w;for(;(w=x.pattern.exec(f.combined))!==null;){let M=w[1]||w[0],{line:$,column:H}=b(f.matchOffset),W=u[$-1]||"",j=$>1?u[$-2]:"";if(!i?.disallowInlineIgnore&&$t(W,j))continue;let ne=A($),Q=We(ne.lines,ne.relativeTargetIdx),ue=Ue(ne.lines,ne.relativeTargetIdx,e,v,$-1),q=Ze(x,M,l,Q,e,ue);if(q.isSuppressed)continue;let U;if(x.minEntropy!==void 0&&(x.id==="generic-api-key"&&i.minEntropyThreshold!==void 0?U=i.minEntropyThreshold:U=x.minEntropy),U!==void 0&&q.evidence.shannonEntropy<U)continue;let ee=e;if(c){let ae=ge.relative(c,e);!ae.startsWith("..")&&!ge.isAbsolute(ae)&&(ee=ae)}let re=qe(x,q.confidence,l),me=Xe(x,M,ee,$,Q.inferredVariable);q.evidence.items.unshift({signal:"ADVERSARIAL_DEOBFUSCATION_RESOLVED",description:f.description,confidenceImpact:10});let xe=Lt(ee),Ie=Ye(M,void 0,c),Ce=`sec_${Ie}_${xe}`,He=ye(M);d.push({id:Ce,fingerprint:Ie,type:x.name,provider:x.provider,file:ee,fullPath:e,line:$,column:H,length:f.matchLength,rawSecret:M,redactedSecret:He,confidence:Math.min(100,q.confidence+5),risk:re.tier,riskAssessment:re,evidence:q.evidence,remediation:me,status:"ACTIVE",detectedAt:new Date().toISOString(),signals:q.evidence.items.map(ae=>ae.description),exampleFix:me.replacementCode,entropy:q.evidence.shannonEntropy})}}return yn(d)}function yn(t){let e=[];for(let n of t){let i=e.findIndex(o=>o.file===n.file&&o.line===n.line&&(o.rawSecret.includes(n.rawSecret)||n.rawSecret.includes(o.rawSecret)));if(i===-1)e.push(n);else{let o=e[i];(o.provider==="Generic Credential"&&n.provider!=="Generic Credential"||n.confidence>o.confidence)&&(e[i]=n)}}return e}var Fe=class{diagnosticCollection;currentFindings=new Map;ignoredFindings=new Set;documentAstCache=new Map;onFindingsChangedEmitter=new F.EventEmitter;onFindingsChanged=this.onFindingsChangedEmitter.event;minEntropy;constructor(){this.diagnosticCollection=F.languages.createDiagnosticCollection("secret-leak-detector")}setMinEntropy(e){this.minEntropy=e}getDiagnosticCollection(){return this.diagnosticCollection}getAllFindings(){let e=[];for(let n of this.currentFindings.values())e.push(...n);return e}clear(){this.diagnosticCollection.clear(),this.currentFindings.clear(),this.documentAstCache.clear(),this.onFindingsChangedEmitter.fire([])}ignoreFinding(e){this.ignoredFindings.add(e);for(let[n,i]of this.currentFindings.entries()){let o=i.filter(s=>s.id!==e);if(o.length!==i.length){this.currentFindings.set(n,o);let s=F.Uri.file(n),r=this.diagnosticCollection.get(s);if(r){let a=r.filter(c=>(typeof c.code=="object"?c.code?.value:c.code)!==e);this.diagnosticCollection.set(s,a)}}}this.onFindingsChangedEmitter.fire(this.getAllFindings())}setIgnoredFindings(e){this.ignoredFindings=new Set(e)}getIgnoredFindings(){return Array.from(this.ignoredFindings)}scanDocument(e){if(e.uri.scheme!=="file")return[];let n=e.getText();if(n.length>5*1024*1024)return[];let i=F.workspace.getWorkspaceFolder(e.uri),o=i?i.uri.fsPath:void 0,s=null,r=this.documentAstCache.get(e.uri.toString());r&&r.version===e.version?s=r.sourceFile:/\.[jt]sx?$|\.m[jt]s$|\.c[jt]s$/i.test(e.uri.fsPath)&&(s=ve(n,e.uri.fsPath),this.documentAstCache.set(e.uri.toString(),{version:e.version,sourceFile:s}));let a={workspaceRoot:o,minEntropyThreshold:this.minEntropy,cachedSourceFile:s},l=de(n,e.uri.fsPath,a).filter(d=>!this.ignoredFindings.has(d.id));this.currentFindings.set(e.uri.fsPath,l);let u=[];for(let d of l){let p=Math.max(0,d.line-1),v=Math.max(0,d.column-1),m=new F.Position(p,v),S=e.offsetAt(m),b=e.positionAt(S+d.length),A=new F.Range(m,b),k=F.DiagnosticSeverity.Warning;d.risk==="CRITICAL"||d.risk==="HIGH"?k=F.DiagnosticSeverity.Error:d.risk==="LOW"&&(k=F.DiagnosticSeverity.Information);let P=typeof d.remediation=="string"?d.remediation:d.remediation?.steps?.[0]||"Migrate to .env",I=new F.Diagnostic(A,`[Secret Leak Detector] ${d.type} detected! Confidence: ${d.confidence}%. ${P}`,k);I.code={value:d.id,target:F.Uri.parse("https://github.com/MokuLakshithReddy/Secret_Leak_Detector")},I.source="Secret Leak Detector",u.push(I)}return this.diagnosticCollection.set(e.uri,u),this.onFindingsChangedEmitter.fire(this.getAllFindings()),l}toDiagnostic(e){let n=Math.max(0,e.line-1),i=Math.max(0,e.column-1),o=new F.Position(n,i),s,r=e.rawSecret||(e.evidence?.surroundingCode?.targetLine?e.redactedSecret:"");if(r&&r.includes(`
`)){let d=r.split(/\r?\n/),p=n+d.length-1,v=d.length>1?d[d.length-1].length:i+d[0].length;s=new F.Position(p,v)}else s=new F.Position(n,i+e.length);let a=new F.Range(o,s),c=F.DiagnosticSeverity.Warning;e.risk==="CRITICAL"||e.risk==="HIGH"?c=F.DiagnosticSeverity.Error:e.risk==="LOW"&&(c=F.DiagnosticSeverity.Information);let l=typeof e.remediation=="string"?e.remediation:e.remediation?.steps?.[0]||"Migrate to .env",u=new F.Diagnostic(a,`[Secret Leak Detector] ${e.type} detected! Confidence: ${e.confidence}%. ${l}`,c);return u.code={value:e.id,target:F.Uri.parse("https://github.com/MokuLakshithReddy/Secret_Leak_Detector")},u.source="Secret Leak Detector",u}setBatchFindings(e){this.diagnosticCollection.clear(),this.currentFindings.clear();for(let[n,i]of e.entries()){let o=i.filter(s=>!this.ignoredFindings.has(s.id));if(this.currentFindings.set(n,o),o.length>0){let s=F.Uri.file(n),r=o.map(a=>this.toDiagnostic(a));this.diagnosticCollection.set(s,r)}}this.onFindingsChangedEmitter.fire(this.getAllFindings())}renameDocument(e,n){let i=this.currentFindings.get(e.fsPath);if(this.removeDocument(e),i&&i.length>0){let o=i.map(r=>({...r,fullPath:n.fsPath,file:n.fsPath}));this.currentFindings.set(n.fsPath,o);let s=o.map(r=>this.toDiagnostic(r));this.diagnosticCollection.set(n,s),this.onFindingsChangedEmitter.fire(this.getAllFindings())}}removeDocument(e){this.diagnosticCollection.delete(e),this.currentFindings.delete(e.fsPath),this.documentAstCache.delete(e.toString()),this.onFindingsChangedEmitter.fire(this.getAllFindings())}dispose(){this.diagnosticCollection.dispose(),this.documentAstCache.clear(),this.onFindingsChangedEmitter.dispose()}};var z=L(require("vscode"));var fe=class{static providedCodeActionKinds=[z.CodeActionKind.QuickFix];diagnosticProvider;constructor(e){this.diagnosticProvider=e}provideCodeActions(e,n,i){let o=[],s=i.diagnostics.filter(a=>a.source==="Secret Leak Detector");if(s.length===0)return o;let r=this.diagnosticProvider.getAllFindings();for(let a of s){let c=typeof a.code=="object"?a.code?.value:a.code,l=r.find(v=>v.id===c);if(!l||e.getText(a.range)!==l.rawSecret)continue;let d=this.createMoveToEnvAction(e,a.range,l);o.push(d);let p=new z.CodeAction("Ignore this finding (False Positive)",z.CodeActionKind.QuickFix);p.command={command:"secret-leak-detector.ignoreFinding",title:"Ignore Finding",arguments:[l.id]},o.push(p)}return o}createMoveToEnvAction(e,n,i){let o=new z.CodeAction(`\u{1F6E1}\uFE0F Move ${i.type} to .env and replace with environment variable`,z.CodeActionKind.QuickFix);return o.isPreferred=!0,o.command={command:"secret-leak-detector.remediateFinding",title:"Move to .env",arguments:[e.uri,n,i]},o}static async executeRemediation(e,n,i){let o=z.workspace.getWorkspaceFolder(e);if(!o){z.window.showErrorMessage("No workspace folder found to save .env file.");return}let s=o.uri.fsPath;if((await z.workspace.openTextDocument(e)).getText(n)!==i.rawSecret){z.window.showErrorMessage("The secret at the target location has changed or was already removed.");return}let a=Ft(i,s);if(!a.success){z.window.showErrorMessage(`Remediation aborted: ${a.message}`);return}z.window.showInformationMessage(`\u{1F6E1}\uFE0F ${a.message}`)}};var _=L(require("vscode")),Le=class{_onDidChangeTreeData=new _.EventEmitter;onDidChangeTreeData=this._onDidChangeTreeData.event;findings=[];dispose(){this._onDidChangeTreeData.dispose()}updateFindings(e){this.findings=e,this._onDidChangeTreeData.fire()}getTreeItem(e){return e}getChildren(e){if(!e){if(this.findings.length===0){let o=new J("No Leaks Detected (Safe)",_.TreeItemCollapsibleState.None);return o.iconPath=new _.ThemeIcon("shield-check",new _.ThemeColor("testing.iconPassed")),o.description="Workspace is clean",Promise.resolve([o])}let n=["CRITICAL","HIGH","MEDIUM","LOW"],i=[];for(let o of n){let s=this.findings.filter(r=>r.risk===o).length;if(s>0){let r=new J(`${o} Risk (${s})`,_.TreeItemCollapsibleState.Expanded,o);o==="CRITICAL"?r.iconPath=new _.ThemeIcon("error",new _.ThemeColor("errorForeground")):o==="HIGH"?r.iconPath=new _.ThemeIcon("warning",new _.ThemeColor("editorWarning.foreground")):o==="MEDIUM"?r.iconPath=new _.ThemeIcon("info",new _.ThemeColor("editorInfo.foreground")):r.iconPath=new _.ThemeIcon("pass",new _.ThemeColor("testing.iconPassed")),i.push(r)}}return Promise.resolve(i)}if(e.contextValue){let n=e.contextValue,i=this.findings.filter(r=>r.risk===n),o=_.workspace.getConfiguration("secretLeakDetector").get("redactSecrets",!0),s=i.map(r=>{let a=new J(`${r.type}`,_.TreeItemCollapsibleState.None),c=o?r.redactedSecret:r.rawSecret,l=typeof r.remediation?.replacementCode=="string"?r.remediation.replacementCode:typeof r.remediation?.envVarName=="string"?`process.env.${r.remediation.envVarName}`:"Migrate to .env";return a.description=`${r.file}:${r.line}`,a.tooltip=new _.MarkdownString(`**${r.type}** (${r.provider})

- **Risk:** ${r.risk}
- **Confidence:** ${r.confidence}%
- **Entropy:** ${r.entropy} bits/char
- **Secret:** \`${c}\`

*Suggested Fix: ${l}*`),a.iconPath=new _.ThemeIcon("key"),a.command={command:"vscode.open",title:"Jump to Secret",arguments:[_.Uri.file(r.fullPath),{selection:new _.Range(r.line-1,r.column-1,r.line-1,r.column-1+r.length)}]},a});return Promise.resolve(s)}return Promise.resolve([])}},$e=class{_onDidChangeTreeData=new _.EventEmitter;onDidChangeTreeData=this._onDidChangeTreeData.event;findingsCount=0;isGit=!0;dispose(){this._onDidChangeTreeData.dispose()}update(e,n){this.findingsCount=e,this.isGit=n,this._onDidChangeTreeData.fire()}getTreeItem(e){return e}getChildren(){let e=[],n=new J(this.findingsCount===0?"Status: Protected":`Status: ${this.findingsCount} Leaks Active`,_.TreeItemCollapsibleState.None);n.iconPath=new _.ThemeIcon(this.findingsCount===0?"check":"alert",this.findingsCount===0?new _.ThemeColor("testing.iconPassed"):new _.ThemeColor("errorForeground")),e.push(n);let i=new J("Run Full Workspace Scan",_.TreeItemCollapsibleState.None);i.iconPath=new _.ThemeIcon("search"),i.command={command:"secret-leak-detector.scanWorkspace",title:"Scan Workspace"},e.push(i);let o=new J("Check Git Staged Changes",_.TreeItemCollapsibleState.None);o.iconPath=new _.ThemeIcon("git-commit"),o.command={command:"secret-leak-detector.scanStaged",title:"Scan Staged Changes"},e.push(o);let s=new J("Open Interactive Dashboard",_.TreeItemCollapsibleState.None);s.iconPath=new _.ThemeIcon("dashboard"),s.command={command:"secret-leak-detector.openDashboard",title:"Open Dashboard"},e.push(s);let r=new J("Install Pre-Commit Hook",_.TreeItemCollapsibleState.None);return r.iconPath=new _.ThemeIcon("terminal"),r.command={command:"secret-leak-detector.installGitHook",title:"Install Hook"},e.push(r),Promise.resolve(e)}},J=class extends _.TreeItem{constructor(e,n,i){super(e,n),this.contextValue=i}};var K=L(require("vscode")),Nt=L(require("crypto")),et=L(require("fs")),ke=L(require("path"));function Qe(t){let e=typeof t.remediation=="string"?t.remediation:t.remediation?.steps?.join("; ")||"Rotate and move to .env",n=t.exampleFix||t.remediation?.replacementCode||"";return{id:t.id,type:t.type,provider:t.provider,file:t.file,fullPath:t.fullPath,line:t.line,column:t.column,redactedSecret:t.redactedSecret,confidence:t.confidence,entropy:t.entropy??0,risk:t.risk,remediationText:e,exampleFix:n}}var le=class t{static currentPanel;static viewType="secretLeakDetectorDashboard";_panel;_extensionUri;_disposables=[];_findings=[];static createOrShow(e,n){let i=K.window.activeTextEditor?K.window.activeTextEditor.viewColumn:void 0;if(t.currentPanel){t.currentPanel._panel.reveal(i),t.currentPanel.updateFindings(n);return}let o=K.window.createWebviewPanel(t.viewType,"\u{1F510} Secret Leak Detector Dashboard",i||K.ViewColumn.One,{enableScripts:!0,retainContextWhenHidden:!0,localResourceRoots:[e]});t.currentPanel=new t(o,e,n)}constructor(e,n,i){this._panel=e,this._extensionUri=n,this._findings=i,this._update(),this._panel.onDidDispose(()=>this.dispose(),null,this._disposables),this._panel.webview.onDidReceiveMessage(async o=>{switch(o.command){case"scanWorkspace":K.commands.executeCommand("secret-leak-detector.scanWorkspace");return;case"scanStaged":K.commands.executeCommand("secret-leak-detector.scanStaged");return;case"installHook":K.commands.executeCommand("secret-leak-detector.installGitHook");return;case"openFile":if(typeof o.file=="string"&&o.file.trim().length>0&&typeof o.line=="number"&&o.line>=1){let s=this._findings.find(a=>a.file===o.file||a.fullPath===o.file);if(!s)return;let r=s.fullPath||s.file;if(!ke.isAbsolute(r)){let a=!1;for(let c of K.workspace.workspaceFolders||[]){let l=ke.resolve(c.uri.fsPath,r);if(et.existsSync(l)){r=l,a=!0;break}}if(!a){let c=K.workspace.workspaceFolders?.[0]?.uri.fsPath||process.cwd();r=ke.resolve(c,r)}}if(et.existsSync(r))try{let a=await K.workspace.openTextDocument(K.Uri.file(r));await K.window.showTextDocument(a,{selection:new K.Range(o.line-1,0,o.line-1,0)})}catch{}}return}},null,this._disposables)}updateFindings(e){this._findings=e;let n=this._findings.map(Qe);this._panel.webview.postMessage({command:"updateData",findings:n})}dispose(){for(t.currentPanel=void 0,this._panel.dispose();this._disposables.length;){let e=this._disposables.pop();e&&e.dispose()}}_update(){this._panel.webview.html=this._getHtmlForWebview()}_getHtmlForWebview(){let e=Nt.randomBytes(16).toString("base64"),n=this._findings.map(Qe),i=JSON.stringify(n).replace(/</g,"\\u003c");return`<!DOCTYPE html>
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
</html>`}};var Zt=require("child_process"),qt=require("util"),E=L(require("fs")),ct=L(require("os")),O=L(require("path"));var G=require("child_process"),Mt=require("util"),ot=L(require("path"));var De=L(require("fs")),Ne=L(require("path")),tt=new Set([".exe",".dll",".so",".dylib",".iso",".dmg",".woff",".woff2",".ttf",".eot",".otf",".mp3",".mp4",".avi",".mov",".wmv",".flv",".mkv",".wav",".pyc",".pyo",".class",".o",".obj",".lib",".a"]),mi=new Set([...tt,".wasm",".pkl",".npy",".parquet",".onnx",".safetensors"]),nt=["**/node_modules/**","node_modules/**","**/.git/**",".git/**","dist/**","build/**","package-lock.json","**/package-lock.json","pnpm-lock.yaml","**/pnpm-lock.yaml","yarn.lock","**/yarn.lock","bun.lockb","**/bun.lockb"],pe=new Map;function kn(t){try{let{execFileSync:e}=require("child_process"),n=process.env.SLD_BASE_REF||process.env.GITHUB_BASE_REF||process.env.CI_MERGE_REQUEST_TARGET_BRANCH_NAME,i=process.env.GITHUB_EVENT_BEFORE||process.env.CI_COMMIT_BEFORE_SHA,o=[];n&&n!=="0000000000000000000000000000000000000000"&&o.push(`origin/${n}`,`refs/remotes/origin/${n}`,n),i&&i!=="0000000000000000000000000000000000000000"&&o.push(i),o.length===0&&o.push("HEAD~1");let s="";try{s=e("git",["rev-parse","HEAD"],{cwd:t,encoding:"utf8",stdio:["pipe","pipe","ignore"]}).trim()}catch{}for(let r of o)if(s)try{if(e("git",["rev-parse",r],{cwd:t,encoding:"utf8",stdio:["pipe","pipe","ignore"]}).trim()===s)continue;return r}catch{continue}else return r;return null}catch{return null}}function it(t){let e=Ne.resolve(t).replace(/\\/g,"/");if(pe.has(e))return pe.get(e);if(!!(process.env.CI||process.env.GITHUB_ACTIONS||process.env.GITLAB_CI))try{let{execFileSync:o}=require("child_process"),s=kn(t);if(s)try{let r=o("git",["show",`${s}:.sldignore`],{cwd:t,encoding:"utf8",stdio:["ignore","pipe","ignore"]});if(r){let a=r.split(/\r?\n/).map(c=>c.trim()).filter(c=>c.length>0&&!c.startsWith("#"));return pe.set(e,a),a}}catch{}return pe.set(e,[]),[]}catch{return pe.set(e,[]),[]}let i=Ne.join(t,".sldignore");if(De.existsSync(i))try{let s=De.readFileSync(i,"utf8").split(/\r?\n/).map(r=>r.trim()).filter(r=>r.length>0&&!r.startsWith("#"));return pe.set(e,s),s}catch{}return pe.set(e,[]),[]}function Sn(t){let e=t.trim().replace(/\\/g,"/"),n=!1;e.endsWith("/")&&(n=!0,e=e.slice(0,-1));let i=e.startsWith("/");i&&(e=e.slice(1));let o="",s=0;for(;s<e.length;)e.slice(s,s+4)==="/**/"?(o+="(?:/|/.*/)",s+=4):e.slice(s,s+3)==="/**"?(o+="(/.*)?",s+=3):e.slice(s,s+3)==="**/"?(o+="(?:^|.*/)",s+=3):e.slice(s,s+2)==="**"?(o+=".*",s+=2):e[s]==="*"?(o+="[^/]*",s+=1):e[s]==="?"?(o+="[^/]",s+=1):[".","+","^","$","(",")","[","]","{","}","|"].includes(e[s])?(o+="\\"+e[s],s+=1):(o+=e[s],s+=1);return n?i||e.includes("/")?new RegExp("^"+o+"(/.*)?$"):new RegExp("(?:^|/)"+o+"(/.*)?$"):!e.includes("/")&&!i?new RegExp("(?:^|/)"+o+"$"):new RegExp("^"+o+"$")}function st(t,e){let n=t.replace(/\\/g,"/").replace(/^\/+/,""),i=e.trim().replace(/\\/g,"/");if(!i||i.startsWith("#"))return!1;if(n===i)return!0;let o=i.startsWith("/"),s=o?i.slice(1):i,r=s.endsWith("/")?s.slice(0,-1):s;if(!s.includes("*")){if(o||s.includes("/")){if(n===r||n.startsWith(r+"/"))return!0}else if(n===r||n.startsWith(r+"/")||n.includes("/"+r+"/"))return!0}try{return Sn(i).test(n)}catch{return!1}}var Me=(0,Mt.promisify)(G.execFile),X=["--literal-pathspecs","-c","core.quotepath=false","-c","diff.noprefix=false","-c","diff.mnemonicPrefix=false","-c","color.diff=never"],Bt=50*1024*1024;function An(t){try{let e=(0,G.execFileSync)("git",["rev-parse","--show-toplevel"],{cwd:t,encoding:"utf8"}).trim();if(e)return ot.resolve(e)}catch{}return t}async function En(t){try{let{stdout:e}=await Me("git",["rev-parse","--show-toplevel"],{cwd:t,encoding:"utf8"}),n=e.trim();if(n)return ot.resolve(n)}catch{}return t}function Kt(t){let e=[],n=[],i=0;for(let s=0;s<t.length;s++)t[s]===0&&(n.push(t.toString("utf8",i,s)),i=s+1);let o=0;for(;o<n.length;){let s=n[o++];if(!s)break;let r=s[0];if(r==="R"||r==="C"){let a=n[o++],c=n[o++];c&&e.push({status:r,path:c.replace(/\\/g,"/"),oldPath:a?a.replace(/\\/g,"/"):void 0})}else{let a=n[o++];a&&e.push({status:r,path:a.replace(/\\/g,"/")})}}return e}function xn(t,e){let n=new Map;if(e.length===0)return n;let i=e.map(s=>`:${s}
`).join(""),o=(0,G.spawnSync)("git",[...X,"cat-file","--batch-check"],{cwd:t,input:i,encoding:"utf8",maxBuffer:64*1024*1024});if(o.error)throw new Error(`git cat-file --batch-check failed: ${o.error.message}`);if(o.status!==0)throw new Error(`git cat-file --batch-check exited with code ${o.status}: ${o.stderr||""}`);if(o.stdout){let s=o.stdout.split(/\r?\n/);for(let r=0;r<e.length;r++){let a=s[r];if(!a)continue;let c=a.split(" ");c.length>=3&&c[1]==="blob"&&n.set(e[r],parseInt(c[2],10)||0)}}return n}function In(t,e){let n=new Map;if(e.length===0)return n;let i=e.map(c=>`:${c}
`).join(""),o=(0,G.spawnSync)("git",[...X,"cat-file","--batch"],{cwd:t,input:i,maxBuffer:64*1024*1024});if(o.error)throw new Error(`git cat-file --batch failed: ${o.error.message}`);if(o.status!==0)throw new Error(`git cat-file --batch exited with code ${o.status}: ${o.stderr?o.stderr.toString("utf8"):""}`);let s=o.stdout;if(!s||s.length===0)return n;let r=0,a=0;for(;r<s.length&&a<e.length;){let c=s.indexOf(10,r);if(c===-1)break;let l=s.toString("utf8",r,c).trim();r=c+1;let u=l.split(" ");if(u.length>=3&&u[1]==="blob"){let d=parseInt(u[2],10),p=s.subarray(r,r+d);n.set(e[a++],p),r+=d,r<s.length&&s[r]===10&&r++}else a++}return n}function Ht(t){let e=new Map,n=t.split(/^diff --git /m);for(let i of n){if(!i.trim())continue;let r=i.split(/\r?\n/)[0].match(/a\/(.+)\s+b\/(.+)/);if(!r)continue;let a=r[2].trim().replace(/\\/g,"/");if(a==="/dev/null")continue;let c=new Set,l=/^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/gm,u;for(;(u=l.exec(i))!==null;){let d=parseInt(u[1],10),p=u[2]!==void 0?parseInt(u[2],10):1;for(let v=0;v<p;v++)c.add(d+v)}c.size>0?e.set(a,c):(i.includes("rename to ")||i.includes("new file mode ")||i.includes("Binary files "))&&e.set(a,new Set([-1]))}return e}function Wt(t,e){if(e.has(-1))return!0;let i=((t.rawSecret||"").match(/\r?\n/g)||[]).length,o=t.line,s=o+i;for(let r=o;r<=s;r++)if(e.has(r))return!0;return!1}function Cn(t){let e=new Set;try{let i=(0,G.execFileSync)("git",[...X,"ls-files","--stage","-z"],{cwd:t,maxBuffer:67108864}).toString("utf8").split("\0");for(let o of i){if(!o)continue;let[s,r]=o.split("	");s&&r&&s.startsWith("160000")&&e.add(r.replace(/\\/g,"/"))}}catch{}return e}async function wn(t){let e=new Set;try{let{stdout:n}=await Me("git",[...X,"ls-files","--stage","-z"],{cwd:t,maxBuffer:67108864}),i=n.split("\0");for(let o of i){if(!o)continue;let[s,r]=o.split("	");s&&r&&s.startsWith("160000")&&e.add(r.replace(/\\/g,"/"))}}catch{}return e}function zt(t,e){let n=An(t),i;try{i=(0,G.execFileSync)("git",[...X,"diff","--cached","-z","--name-status","--no-color","--no-ext-diff","--src-prefix=a/","--dst-prefix=b/"],{cwd:n,maxBuffer:64*1024*1024})}catch(g){return{status:"ERROR",findings:[],error:`git diff --cached failed: ${g.message||String(g)}`}}let o=Kt(i),s=Cn(n),r=o.filter(g=>g.status!=="D"&&!s.has(g.path));if(r.length===0)return{status:"CLEAN",findings:[],skippedFiles:[],filesScanned:0};let a=[...nt,...it(n)],c=[],l=[],u=[];for(let g of r){let y=g.path,C=a.find(R=>st(y,R));if(C){l.push({path:y,pattern:C});continue}u.push(y)}if(u.length===0)return{status:"CLEAN",findings:[],skippedFiles:c,ignoredFiles:l,filesScanned:0};let d;try{d=xn(n,u)}catch(g){return{status:"ERROR",findings:[],error:g.message||String(g)}}let p=[],v=e?.maxFileSize??Bt;for(let g of u){let y=d.get(g);if(y===void 0)return{status:"ERROR",findings:[],error:`Could not inspect staged blob size for '${g}': buffer truncated or process failed.`};if(y>v){let C=(v/1048576).toFixed(0);if(e?.ignoreSkipped===!0){c.push({path:g,reason:`File size (${(y/(1024*1024)).toFixed(1)}MB) exceeds ${C}MB limit`});continue}return{status:"ERROR",findings:[],error:`File '${g}' (${(y/(1024*1024)).toFixed(1)}MB) exceeds ${C}MB limit. Use --ignore-skipped to bypass.`}}p.push(g)}if(p.length===0)return e?.failOnSkipped&&c.length>0?{status:"ERROR",findings:[],skippedFiles:c,ignoredFiles:l,filesScanned:0,error:`Strict mode (failOnSkipped): ${c.length} file(s) were skipped during staged scan: ${c.map(g=>g.path).join(", ")}`}:{status:"CLEAN",findings:[],skippedFiles:c,ignoredFiles:l,filesScanned:0};let m;try{m=In(n,p)}catch(g){return{status:"ERROR",findings:[],error:g.message||String(g)}}let S=new Map;for(let g of p){let y=m.get(g);if(!y)return{status:"ERROR",findings:[],error:`Could not read staged blob for '${g}': buffer truncated or read failed.`};let C=ce(y);if(C===null){c.push({path:g,reason:"Binary content detected"});continue}S.set(g,C)}let b=Array.from(S.keys());if(b.length===0)return e?.failOnSkipped&&c.length>0?{status:"ERROR",findings:[],skippedFiles:c,ignoredFiles:l,filesScanned:0,error:`Strict mode (failOnSkipped): ${c.length} file(s) were skipped during staged scan: ${c.map(g=>g.path).join(", ")}`}:{status:"CLEAN",findings:[],skippedFiles:c,ignoredFiles:l,filesScanned:0};let A="",k=50;for(let g=0;g<b.length;g+=k){let y=b.slice(g,g+k);try{let C=(0,G.execFileSync)("git",[...X,"diff","--cached","-U0","--no-color","--no-ext-diff","--no-textconv","--src-prefix=a/","--dst-prefix=b/","--",...y],{cwd:n,encoding:"utf8",maxBuffer:67108864});A+=`
`+C}catch{A="";break}}let P=Ht(A),I=[],D=0;for(let g of b){let y=S.get(g);if(!y)continue;let C=P.get(g)||new Set([-1]),R={workspaceRoot:n,disallowInlineIgnore:e?.disallowInlineIgnore},T=de(y,g,R);D++;let f=[];for(let x of T)Wt(x,C)&&f.push(x);f.length>0&&I.push(...f)}return e?.failOnSkipped&&c.length>0?{status:"ERROR",findings:I,skippedFiles:c,ignoredFiles:l,filesScanned:D,error:`Strict mode (failOnSkipped): ${c.length} file(s) were skipped during staged scan: ${c.map(g=>g.path).join(", ")}`}:{status:I.length>0?"FINDINGS":"CLEAN",findings:I,skippedFiles:c,ignoredFiles:l,filesScanned:D}}async function Gt(t,e){let n=await En(t),i;try{let{stdout:g}=await Me("git",[...X,"diff","--cached","-z","--name-status","--no-color","--no-ext-diff","--src-prefix=a/","--dst-prefix=b/"],{cwd:n,maxBuffer:67108864,encoding:"buffer"});i=Buffer.isBuffer(g)?g:Buffer.from(g)}catch(g){return{status:"ERROR",findings:[],error:`git diff --cached failed: ${g.message||String(g)}`}}let o=Kt(i),s=await wn(n),r=o.filter(g=>g.status!=="D"&&!s.has(g.path));if(r.length===0)return{status:"CLEAN",findings:[],skippedFiles:[],filesScanned:0};let a=[...nt,...it(n)],c=[],l=[],u=[];for(let g of r){let y=g.path,C=a.find(R=>st(y,R));if(C){l.push({path:y,pattern:C});continue}u.push(y)}if(u.length===0)return{status:"CLEAN",findings:[],skippedFiles:c,ignoredFiles:l,filesScanned:0};let d=new Map;try{let g=u.map(f=>`:${f}
`).join(""),y=(0,G.spawn)("git",[...X,"cat-file","--batch-check"],{cwd:n}),C="",R="";y.stdout.on("data",f=>C+=f.toString("utf8")),y.stderr.on("data",f=>R+=f.toString("utf8")),y.stdin.write(g),y.stdin.end(),await new Promise((f,x)=>{y.on("error",x),y.on("close",w=>{w!==0?x(new Error(`git cat-file --batch-check exited with code ${w}: ${R}`)):f()})});let T=C.split(/\r?\n/);for(let f=0;f<u.length;f++){let x=T[f];if(!x)continue;let w=x.split(" ");w.length>=3&&w[1]==="blob"&&d.set(u[f],parseInt(w[2],10)||0)}}catch(g){return{status:"ERROR",findings:[],error:g.message||String(g)}}let p=[],v=e?.maxFileSize??Bt;for(let g of u){let y=d.get(g);if(y===void 0)return{status:"ERROR",findings:[],error:`Could not inspect staged blob size for '${g}': buffer truncated or process failed.`};if(y>v){let C=(v/1048576).toFixed(0);if(e?.ignoreSkipped===!0){c.push({path:g,reason:`File size (${(y/(1024*1024)).toFixed(1)}MB) exceeds ${C}MB limit`});continue}return{status:"ERROR",findings:[],error:`File '${g}' (${(y/(1024*1024)).toFixed(1)}MB) exceeds ${C}MB limit. Use --ignore-skipped to bypass.`}}p.push(g)}if(p.length===0)return e?.failOnSkipped&&c.length>0?{status:"ERROR",findings:[],skippedFiles:c,ignoredFiles:l,filesScanned:0,error:`Strict mode (failOnSkipped): ${c.length} file(s) were skipped during staged scan: ${c.map(g=>g.path).join(", ")}`}:{status:"CLEAN",findings:[],skippedFiles:c,ignoredFiles:l,filesScanned:0};let m=new Map;try{let g=p.map(w=>`:${w}
`).join(""),y=(0,G.spawn)("git",[...X,"cat-file","--batch"],{cwd:n}),C=[],R="";y.stdout.on("data",w=>C.push(w)),y.stderr.on("data",w=>R+=w.toString("utf8")),y.stdin.write(g),y.stdin.end(),await new Promise((w,M)=>{y.on("error",M),y.on("close",$=>{$!==0?M(new Error(`git cat-file --batch exited with code ${$}: ${R}`)):w()})});let T=Buffer.concat(C),f=0,x=0;for(;f<T.length&&x<p.length;){let w=T.indexOf(10,f);if(w===-1)break;let M=T.toString("utf8",f,w).trim();f=w+1;let $=M.split(" ");if($.length>=3&&$[1]==="blob"){let H=parseInt($[2],10),W=T.subarray(f,f+H);m.set(p[x++],W),f+=H,f<T.length&&T[f]===10&&f++}else x++}}catch(g){return{status:"ERROR",findings:[],error:g.message||String(g)}}let S=new Map;for(let g of p){let y=m.get(g);if(!y)return{status:"ERROR",findings:[],error:`Could not read staged blob for '${g}': buffer truncated or read failed.`};let C=ce(y);if(C===null){c.push({path:g,reason:"Binary content detected"});continue}S.set(g,C)}let b=Array.from(S.keys());if(b.length===0)return e?.failOnSkipped&&c.length>0?{status:"ERROR",findings:[],skippedFiles:c,ignoredFiles:l,filesScanned:0,error:`Strict mode (failOnSkipped): ${c.length} file(s) were skipped during staged scan: ${c.map(g=>g.path).join(", ")}`}:{status:"CLEAN",findings:[],skippedFiles:c,ignoredFiles:l,filesScanned:0};let A="",k=50;for(let g=0;g<b.length;g+=k){let y=b.slice(g,g+k);try{let{stdout:C}=await Me("git",[...X,"diff","--cached","-U0","--no-color","--no-ext-diff","--no-textconv","--src-prefix=a/","--dst-prefix=b/","--",...y],{cwd:n,encoding:"utf8",maxBuffer:67108864});A+=`
`+C}catch{}}let P=Ht(A),I=[],D=0;for(let g of b){let y=S.get(g);if(!y)continue;let C=P.get(g)||new Set([-1]),R={workspaceRoot:n,disallowInlineIgnore:e?.disallowInlineIgnore},T=de(y,g,R);D++;let f=[];for(let x of T)Wt(x,C)&&f.push(x);f.length>0&&I.push(...f)}return e?.failOnSkipped&&c.length>0?{status:"ERROR",findings:I,skippedFiles:c,ignoredFiles:l,filesScanned:D,error:`Strict mode (failOnSkipped): ${c.length} file(s) were skipped during staged scan: ${c.map(g=>g.path).join(", ")}`}:{status:I.length>0?"FINDINGS":"CLEAN",findings:I,skippedFiles:c,ignoredFiles:l,filesScanned:D}}var at=["LOW","MEDIUM","HIGH","CRITICAL"],rt={LOW:1,MEDIUM:2,HIGH:3,CRITICAL:4},V="HIGH";function _n(t){return typeof t=="string"&&at.includes(t.toUpperCase())}function Se(t,e=V){return _n(t)?t.toUpperCase():e}function Vt(t,e=V){return(rt[t]||0)>=(rt[e]||rt.CRITICAL)}var Ae="# [SLD_HOOK_MANAGED]";function Ut(t=V,e,n,i=!0,o=!0,s=!1){let r=at.includes(t)?t:V,a=e?e.replace(/\\/g,"/"):"",c=a?a.replace(/'/g,"'\\''"):"",l=n?n.replace(/\\/g,"/"):"",u=l?l.replace(/'/g,"'\\''"):"",d=u?`# Resolved Node.js executable (prefer pinned runtime, fallback to system node on PATH)
if [ -n '${u}' ] && [ -x '${u}' ]; then
  NODE_CMD='${u}'
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
fi`,p=a?`# Scanner pinned to bundled CLI path
PINNED_CLI='${c}'
if [ -n "$PINNED_CLI" ] && [ -f "$PINNED_CLI" ]; then
  if [ -z "$NODE_CMD" ]; then
    echo ""
    echo "\u274C COMMIT BLOCKED: Node.js runtime not found on PATH (exit 127)."
    echo "   The pre-commit hook requires Node.js (>=18) to execute the scanner."
    echo "   Ensure 'node' is in your PATH or configure your Git client environment."
    exit 127
  fi
  NODE_MAJOR=$("$NODE_CMD" -e 'process.stdout.write(process.versions.node.split(".")[0])' 2>/dev/null || echo "0")
  if [ "$NODE_MAJOR" -gt 0 ] && [ "$NODE_MAJOR" -lt 18 ]; then
    echo ""
    echo "\u274C COMMIT BLOCKED: Node.js runtime is too old (v$NODE_MAJOR detected, >=18 required)."
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
  # If pinned CLI was in an extension/editor folder that was uninstalled, auto-recover:
  case "$PINNED_CLI" in
    *extensions*|*globalStorage*|*.vscode*|*AppData*|*.config*)
      if [ "$SLD_STRICT" = "1" ] || [ "$(git config --bool secret-leak-detector.strict 2>/dev/null)" = "true" ]; then
        echo ""
        echo "\u274C COMMIT BLOCKED (strict mode): Secret Leak Detector scanner ($PINNED_CLI) is unavailable."
        exit 2
      fi
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
  exit 2
fi`:`# Scanner determined from environment or global binary (never ./dist/cli.js relative to repo)
if [ -n "$SLD_CLI_PATH" ] && [ -f "$SLD_CLI_PATH" ]; then
  if [ -z "$NODE_CMD" ]; then
    echo ""
    echo "\u274C COMMIT BLOCKED: Node.js runtime not found on PATH (exit 127)."
    echo "   The pre-commit hook requires Node.js (>=18) to execute the scanner."
    exit 127
  fi
  NODE_MAJOR=$("$NODE_CMD" -e 'process.stdout.write(process.versions.node.split(".")[0])' 2>/dev/null || echo "0")
  if [ "$NODE_MAJOR" -gt 0 ] && [ "$NODE_MAJOR" -lt 18 ]; then
    echo ""
    echo "\u274C COMMIT BLOCKED: Node.js runtime is too old (v$NODE_MAJOR detected, >=18 required)."
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
${Ae}
# Secret Leak Detector Pre-Commit Hook
# Intercepts git commit and blocks unredacted credentials before they leave the machine.
#
# Severity policy (single source of truth: src/core/policy.ts):
#   Blocks findings at ${r} and above (LOW < MEDIUM < HIGH < CRITICAL).
#   Lower tiers are reported but do not block.
#
# Fail-closed: if the scanner cannot be executed, the commit is BLOCKED.
SLD_FAIL_ON="${r}"
SLD_BLOCK_COMMITS="${i?"1":"0"}"
SLD_DISALLOW_INLINE_DEFAULT="${o?"1":"0"}"
SLD_FAIL_ON_SKIPPED_DEFAULT="${s?"1":"0"}"

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
if [ "$SLD_FAIL_ON_SKIPPED" = "1" ] || [ "$SLD_FAIL_ON_SKIPPED_DEFAULT" = "1" ] || [ "$SLD_STRICT" = "1" ] || [ "$(git config --bool secret-leak-detector.fail-on-skipped 2>/dev/null)" = "true" ] || [ "$(git config --bool secret-leak-detector.strict 2>/dev/null)" = "true" ]; then
  FAIL_ON_SKIPPED="--fail-on-skipped"
fi

${d}

${p}

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
`}var jt=(0,qt.promisify)(Zt.execFile);function Ke(t){try{let e=O.join(ct.homedir(),".sld");E.existsSync(e)||E.mkdirSync(e,{recursive:!0});let n=O.join(e,"installed-hooks.json"),i=[];if(E.existsSync(n))try{let s=JSON.parse(E.readFileSync(n,"utf8"));Array.isArray(s)&&(i=s.filter(r=>typeof r=="string"))}catch(s){console.warn(`[Secret Leak Detector] Warning reading installed hooks registry: ${s?.message||s}`)}let o=O.resolve(t);i.includes(o)||(i.push(o),E.writeFileSync(n,JSON.stringify(i,null,2),"utf8"))}catch(e){console.warn(`[Secret Leak Detector] Warning updating installed hooks registry: ${e?.message||e}`)}}function Be(t){try{let e=O.join(ct.homedir(),".sld","installed-hooks.json");if(E.existsSync(e)){let n=JSON.parse(E.readFileSync(e,"utf8"));if(Array.isArray(n)){let i=O.resolve(t),o=n.filter(s=>typeof s=="string"&&O.resolve(s)!==i);E.writeFileSync(e,JSON.stringify(o,null,2),"utf8")}}}catch(e){console.warn(`[Secret Leak Detector] Warning unrecording hook from registry: ${e?.message||e}`)}}var oe=class{workspaceRoot;cliPath;onWarn;constructor(e,n,i){if(this.workspaceRoot=e,typeof n=="function"?this.onWarn=n:n&&E.existsSync(n)?(this.cliPath=n,this.onWarn=i):this.onWarn=i,!this.cliPath)if(process.env.SLD_CLI_PATH&&E.existsSync(process.env.SLD_CLI_PATH))this.cliPath=process.env.SLD_CLI_PATH;else{let o=[O.resolve(__dirname,"cli.js"),O.resolve(__dirname,"../cli/index.js"),O.resolve(__dirname,"../../dist/cli.js")];this.cliPath=o.find(s=>E.existsSync(s))}}async isGitRepo(){try{return await jt("git",["rev-parse","--is-inside-work-tree"],{cwd:this.workspaceRoot}),!0}catch{return!1}}async scanStagedChanges(e){return Gt(this.workspaceRoot,e)}scanStagedChangesSync(e){return zt(this.workspaceRoot,e)}formatTerminalBlockedMessage(e){let i=e.filter(c=>c.risk==="CRITICAL")[0]||e[0],o=typeof i.remediation=="string"?i.remediation:i.remediation?.steps?.join(`
`)||"Rotate and move to .env",s=i.evidence?.items?.map(c=>`  - [${c.confidenceImpact>=0?"+":""}${c.confidenceImpact}] ${c.description}`).join(`
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
${s}

Recommended Remediation:
------------------------------------------------------------
${o}

Example Fix:
  ${i.exampleFix||i.remediation?.replacementCode}

After fixing:
  1. Replace the secret in ${i.file} with an environment variable.
  2. Add the sensitive value to your local .env (ensure .env is in .gitignore!).
  3. Run 'git add ${i.file}'
  4. Run your 'git commit' again.
============================================================
`}async resolveHooksDir(){try{let{stdout:e}=await jt("git",["rev-parse","--git-path","hooks"],{cwd:this.workspaceRoot}),n=e.trim();return O.isAbsolute(n)?n:O.resolve(this.workspaceRoot,n)}catch{return O.join(this.workspaceRoot,".git","hooks")}}async getHookPath(){let e=await this.resolveHooksDir();return O.join(e,"pre-commit")}async installPreCommitHook(e,n,i=!0,o=V,s=!0,r=!1){if(!await this.isGitRepo())return{success:!1,message:"Workspace is not a Git repository."};let a=e||this.cliPath;if(!a||!E.existsSync(a))return{success:!1,message:`Cannot install pre-commit hook: bundled CLI binary not found at '${a||"undefined"}'. Installation aborted.`};let c=await this.resolveHooksDir();if(!E.existsSync(c))try{E.mkdirSync(c,{recursive:!0})}catch(u){return{success:!1,message:`Could not create hooks directory (${c}): ${u}`}}let l=O.join(c,"pre-commit.sld.lock");try{E.writeFileSync(l,String(process.pid),{flag:"wx"})}catch(u){if(u?.code==="EEXIST")try{let d=E.statSync(l);if(Date.now()-d.mtimeMs>1e4)E.unlinkSync(l),E.writeFileSync(l,String(process.pid),{flag:"wx"});else return{success:!1,message:"Another hook operation is currently in progress (lock active)."}}catch{return{success:!1,message:"Another hook operation is currently in progress (lock active)."}}else return{success:!1,message:`Could not acquire hook lock: ${u?.message||u}`}}try{let u=O.join(c,"pre-commit"),d=Date.now(),p=O.join(c,`pre-commit.sld-backup.${d}`),v=O.join(c,"pre-commit.sld-backup.latest"),m=Ae;if(E.existsSync(u))try{let A=E.statSync(u).mode,k=E.readFileSync(u,"utf8");if(!k.includes(m)){let P=`${p}.tmp.${process.pid}`;E.writeFileSync(P,k,{mode:A}),E.renameSync(P,p);let I=`${v}.tmp.${process.pid}`;E.writeFileSync(I,p,"utf8"),E.renameSync(I,v)}}catch(b){return{success:!1,message:`Could not backup existing hook: ${b}`}}if(/[\/\\](?:_npx|Temp|tmp)[\/\\]/i.test(a)){let b=`\u26A0\uFE0F Warning: Pre-commit hook is pinning a temporary/npx CLI path: '${a}'. This path may be deleted automatically by your system. Consider installing secret-leak-detector globally or locally.`;this.onWarn?this.onWarn(b):console.warn(b)}let S=Ut(o,a,n,i,s,r);try{let b=O.join(c,`pre-commit.tmp.${process.pid}`);return E.writeFileSync(b,S,{mode:493}),E.renameSync(b,u),Ke(u),{success:!0,message:`Pre-commit hook successfully installed to ${u}`}}catch(b){return{success:!1,message:`Failed to write hook file: ${b}`}}}finally{try{E.existsSync(l)&&E.unlinkSync(l)}catch{}}}async ensureHookIsPinned(e,n,i=!0,o=V,s=!0,r=!1){if(!e||!E.existsSync(e)||!await this.isGitRepo())return!1;let a=await this.resolveHooksDir(),c=O.join(a,"pre-commit");if(!E.existsSync(c))return!1;try{let l=E.readFileSync(c,"utf8");if(!l.includes(Ae))return!1;let u=e.replace(/\\/g,"/"),d=`SLD_FAIL_ON="${o}"`,p=`SLD_BLOCK_COMMITS="${i?"1":"0"}"`,v=`SLD_DISALLOW_INLINE_DEFAULT="${s?"1":"0"}"`,m=`SLD_FAIL_ON_SKIPPED_DEFAULT="${r?"1":"0"}"`,S=l.includes("ELECTRON_RUN_AS_NODE=1");if(!l.includes(u)||!l.includes(d)||!l.includes(p)||!l.includes(v)||!l.includes(m)||!S)return(await this.installPreCommitHook(e,n,i,o,s,r)).success}catch{return!1}return!0}async uninstallPreCommitHook(){let e=await this.resolveHooksDir(),n=O.join(e,"pre-commit"),i=O.join(e,"pre-commit.sld-backup.latest"),o=O.join(e,"pre-commit.sld.lock");if(!E.existsSync(n))return{success:!0,message:"No pre-commit hook found to uninstall."};try{E.writeFileSync(o,String(process.pid),{flag:"wx"})}catch(s){if(s?.code==="EEXIST")try{let r=E.statSync(o);if(Date.now()-r.mtimeMs>1e4)E.unlinkSync(o),E.writeFileSync(o,String(process.pid),{flag:"wx"});else return{success:!1,message:"Another hook operation is currently in progress (lock active)."}}catch{return{success:!1,message:"Another hook operation is currently in progress (lock active)."}}else return{success:!1,message:`Could not acquire hook lock: ${s?.message||s}`}}try{if(!E.readFileSync(n,"utf8").includes(Ae))return{success:!1,message:"Existing pre-commit hook is not managed by Secret Leak Detector; refusing to delete user hook."};if(E.existsSync(i)){let r=E.readFileSync(i,"utf8").trim(),a=O.resolve(r),c=O.resolve(e),l=O.basename(a);if(O.dirname(a)===c&&/^pre-commit\.sld-backup\.\d+$/.test(l)&&E.existsSync(a)){let u=E.statSync(a),d=O.join(e,`pre-commit.restore.tmp.${process.pid}`);E.copyFileSync(a,d);try{E.chmodSync(d,u.mode)}catch{}return E.renameSync(d,n),E.unlinkSync(a),E.unlinkSync(i),Be(n),{success:!0,message:"Uninstalled SLD hook and restored original pre-commit hook."}}else try{E.unlinkSync(i)}catch{}}return E.unlinkSync(n),Be(n),{success:!0,message:"Removed Secret Leak Detector pre-commit hook."}}catch(s){return{success:!1,message:`Failed to uninstall hook: ${s.message}`}}finally{try{E.existsSync(o)&&E.unlinkSync(o)}catch{}}}};var B,Ee=new Map;function Rn(t){B=h.window.createOutputChannel("Secret Leak Detector"),t.subscriptions.push(B),B.appendLine("\u{1F510} [Secret Leak Detector] Extension activated.");let e=new Fe;t.subscriptions.push(e),t.subscriptions.push(h.languages.registerCodeActionsProvider({scheme:"file"},new fe(e),{providedCodeActionKinds:fe.providedCodeActionKinds}));let n=new Le,i=new $e;t.subscriptions.push(n),t.subscriptions.push(i),t.subscriptions.push(h.window.registerTreeDataProvider("secret-leak-detector.findingsView",n)),t.subscriptions.push(h.window.registerTreeDataProvider("secret-leak-detector.overviewView",i));let o=h.workspace.workspaceFolders?.[0],s=o?o.uri.fsPath:process.cwd(),r=new oe(s,d=>B.appendLine(d));e.onFindingsChanged(d=>{n.updateFindings(d),i.update(d.length,!0),le.currentPanel&&le.currentPanel.updateFindings(d)});let a=()=>h.workspace.getConfiguration("secretLeakDetector");function c(){let p=a().get("minEntropy");e.setMinEntropy(typeof p=="number"&&p>0?p:void 0);let v=t.workspaceState.get("ignoredFindings",[]);e.setIgnoredFindings(v)}c();let l=Z.join(t.extensionPath,"dist","cli.js");try{let d=t.globalStorageUri.fsPath;N.existsSync(d)||N.mkdirSync(d,{recursive:!0});let p=Z.join(d,"cli.js");N.existsSync(l)&&(N.copyFileSync(l,p),l=p)}catch{}async function u(d){let p=h.workspace.workspaceFolders||[],v=a().get("blockGitCommits",!0),m=Se(a().get("failOn",V)),S=a().get("disallowInlineIgnore",!1),b=a().get("failOnSkipped",!1),A=Z.join(t.globalStorageUri.fsPath,"installed-hooks.json"),k=[];try{if(N.existsSync(A)){let I=JSON.parse(N.readFileSync(A,"utf8"));Array.isArray(I)&&(k=I.filter(D=>typeof D=="string"))}}catch{}let P=new Set(k);for(let I of p){let D=new oe(I.uri.fsPath,g=>B.appendLine(g));if(await D.isGitRepo()){await D.ensureHookIsPinned(d,process.execPath,v,m,S,b).catch(()=>{});try{let g=await D.getHookPath();P.add(g)}catch{}}}try{N.writeFileSync(A,JSON.stringify(Array.from(P),null,2),"utf8")}catch{}}N.existsSync(l)&&u(l).catch(()=>{}),t.subscriptions.push(h.workspace.onDidChangeWorkspaceFolders(async()=>{N.existsSync(l)&&await u(l).catch(()=>{})})),t.subscriptions.push(h.workspace.onDidChangeConfiguration(d=>{d.affectsConfiguration("secretLeakDetector")&&(c(),N.existsSync(l)&&u(l).catch(()=>{}),h.window.activeTextEditor&&e.scanDocument(h.window.activeTextEditor.document))})),h.window.activeTextEditor&&e.scanDocument(h.window.activeTextEditor.document),t.subscriptions.push(h.workspace.onDidSaveTextDocument(d=>{a().get("enableRealtimeScanning",!0)&&e.scanDocument(d)})),t.subscriptions.push(h.workspace.onDidOpenTextDocument(d=>{a().get("enableRealtimeScanning",!0)&&e.scanDocument(d)})),t.subscriptions.push(h.workspace.onDidChangeTextDocument(d=>{if(!a().get("enableRealtimeScanning",!0))return;let p=d.document.uri.toString(),v=Ee.get(p);v&&clearTimeout(v);let m=setTimeout(()=>{e.scanDocument(d.document),Ee.delete(p)},350);Ee.set(p,m)})),t.subscriptions.push(h.workspace.onDidDeleteFiles(d=>{d.files.forEach(p=>e.removeDocument(p))})),t.subscriptions.push(h.workspace.onDidRenameFiles(d=>{d.files.forEach(p=>e.renameDocument(p.oldUri,p.newUri))})),t.subscriptions.push(h.commands.registerCommand("secret-leak-detector.scanWorkspace",async()=>{if(!h.workspace.workspaceFolders||h.workspace.workspaceFolders.length===0){h.window.showWarningMessage("Please open a workspace folder or repository to scan for secrets.");return}await h.window.withProgress({location:h.ProgressLocation.Notification,title:"\u{1F510} Scanning workspace for secret leaks...",cancellable:!0},async(d,p)=>{let v=a().get("excludeGlobs",[]),m=v.length>0?`{${v.join(",")}}`:void 0,S=1e3,b=await h.workspace.findFiles("**/*",m,S),A=new Map,k=[],P=0,I=0,D=b.length;for(let T=0;T<D;T++){if(p.isCancellationRequested){h.window.showInformationMessage("Secret Leak Detector: Workspace scan was cancelled.");return}let f=b[T],x=Z.extname(f.fsPath).toLowerCase();if(tt.has(x)){I++;continue}try{if((await h.workspace.fs.stat(f)).size>50*1024*1024){I++;continue}let M=await h.workspace.fs.readFile(f),$=ce(Buffer.from(M));if($===null){I++;continue}let H=h.workspace.getWorkspaceFolder(f),W={workspaceRoot:H?H.uri.fsPath:void 0,minEntropyThreshold:a().get("minEntropy")},j=de($,f.fsPath,W);A.set(f.fsPath,j),k.push(...j),P++}catch{I++}d.report({message:`${P}/${D} files scanned`,increment:1/(D||1)*100})}e.setBatchFindings(A);let g=b.length>=S,y=`Scanned ${P} files.`;g&&(y+=` \u26A0\uFE0F Scan was capped at ${S} files.`),I>0&&(y+=` (${I} large or binary files skipped)`);let C=new Set(e.getIgnoredFindings()),R=k.filter(T=>!C.has(T.id));if(P===0)h.window.showWarningMessage(`\u26A0\uFE0F Workspace scan complete: 0 files were scanned. ${y}`);else if(R.length===0)h.window.showInformationMessage(`\u2705 Scan complete: ${y} No unignored secrets or credentials detected!`);else{let T=R.filter(f=>f.risk==="CRITICAL").length;h.window.showErrorMessage(`\u{1F6A8} Found ${R.length} leaked secret(s) (${T} Critical)! ${y}`,"Open Dashboard","View Findings").then(f=>{f==="Open Dashboard"?h.commands.executeCommand("secret-leak-detector.openDashboard"):f==="View Findings"&&h.commands.executeCommand("workbench.view.extension.secret-leak-detector-sidebar")})}})})),t.subscriptions.push(h.commands.registerCommand("secret-leak-detector.scanStaged",async()=>{let d=h.workspace.workspaceFolders||[];if(d.length===0){h.window.showWarningMessage("Please open a Git repository in VS Code to scan staged changes.");return}B.clear(),B.appendLine("\u{1F510} [Secret Leak Detector] Scanning Git staged changes..."),B.show(!0);let p=a().get("blockGitCommits",!0),v=Se(a().get("failOn",V)),m=a().get("ignoreSkipped",!0),S=a().get("failOnSkipped",!1),b=new Set;for(let R of d)await new oe(R.uri.fsPath).isGitRepo()&&b.add(R.uri.fsPath);if(b.size===0){h.window.showWarningMessage("None of the opened workspace folders are Git repositories.");return}let A=[],k=[],P=[];for(let R of b){let f=await new oe(R,x=>B.appendLine(x)).scanStagedChanges({ignoreSkipped:m,failOnSkipped:S});f.status==="ERROR"&&P.push(`${R}: ${f.error}`),f.skippedFiles&&k.push(...f.skippedFiles),f.findings&&A.push(...f.findings)}if(P.length>0){let R=`\u274C Git scan encountered error(s):
${P.join(`
`)}`;B.appendLine(R),h.window.showErrorMessage(R,"View Output").then(T=>{T==="View Output"&&B.show(!0)});return}if(k.length>0){B.appendLine(`\u2139\uFE0F  Skipped ${k.length} binary or oversized file(s):`);for(let R of k)B.appendLine(`   \u2022 ${R.path}: ${R.reason}`)}if(A.length===0){k.length>0?(B.appendLine(`\u26A0\uFE0F  Staged scan completed with warnings: ${k.length} uninspected file(s) skipped.`),h.window.showWarningMessage(`\u26A0\uFE0F Git staged changes scanned with warnings: ${k.length} uninspected file(s) skipped.`)):(B.appendLine("\u2705 All staged changes are clean! No credentials detected."),h.window.showInformationMessage("\u2705 Git staged changes are safe to commit."));return}let I=A.filter(R=>Vt(R.risk,v)),g=new oe(s).formatTerminalBlockedMessage(I.length>0?I:A);B.appendLine(g);let C=p&&I.length>0?`\u274C COMMIT BLOCKED: ${I.length} secret(s) at or above ${v} detected in staged changes!`:`\u26A0\uFE0F WARNING: ${A.length} secret(s) detected in staged changes (none block at the ${v} threshold).`;h.window.showErrorMessage(C,"Open Dashboard","View Output").then(R=>{R==="Open Dashboard"?le.createOrShow(t.extensionUri,A):R==="View Output"&&B.show(!0)})})),t.subscriptions.push(h.commands.registerCommand("secret-leak-detector.openDashboard",()=>{le.createOrShow(t.extensionUri,e.getAllFindings())})),t.subscriptions.push(h.commands.registerCommand("secret-leak-detector.installGitHook",async()=>{if((h.workspace.workspaceFolders||[]).length===0){h.window.showWarningMessage("Please open a Git repository in VS Code before installing the pre-commit hook.");return}let p=a().get("blockGitCommits",!0),v=Se(a().get("failOn",V)),m=a().get("disallowInlineIgnore",!0),S=a().get("failOnSkipped",!1),b=await r.installPreCommitHook(l,process.execPath,p,v,m,S);if(b.success){try{let A=Z.join(t.globalStorageUri.fsPath,"installed-hooks.json"),k=await r.getHookPath(),P=[];if(N.existsSync(A)){let I=JSON.parse(N.readFileSync(A,"utf8"));Array.isArray(I)&&(P=I.filter(D=>typeof D=="string"))}P.includes(k)||(P.push(k),N.writeFileSync(A,JSON.stringify(P,null,2),"utf8")),Ke(k)}catch(A){B.appendLine(`[Registry] Error updating hooks record: ${A?.message||A}`)}h.window.showInformationMessage(`\u{1F6E1}\uFE0F ${b.message}`)}else h.window.showErrorMessage(`Failed to install hook: ${b.message}`)})),t.subscriptions.push(h.commands.registerCommand("secret-leak-detector.installGitHookStrict",async()=>{if((h.workspace.workspaceFolders||[]).length===0){h.window.showWarningMessage("Please open a Git repository in VS Code before installing the pre-commit hook.");return}let p=a().get("blockGitCommits",!0),v=Se(a().get("failOn",V)),m=await r.installPreCommitHook(l,process.execPath,p,v,!0,!0);if(m.success){try{let S=Z.join(t.globalStorageUri.fsPath,"installed-hooks.json"),b=await r.getHookPath(),A=[];if(N.existsSync(S)){let k=JSON.parse(N.readFileSync(S,"utf8"));Array.isArray(k)&&(A=k.filter(P=>typeof P=="string"))}A.includes(b)||(A.push(b),N.writeFileSync(S,JSON.stringify(A,null,2),"utf8")),Ke(b)}catch(S){B.appendLine(`[Registry] Error updating hooks record: ${S?.message||S}`)}h.window.showInformationMessage(`\u{1F6E1}\uFE0F ${m.message} (Strict Mode: Fail on Skipped & No Inline Ignore)`)}else h.window.showErrorMessage(`Failed to install hook: ${m.message}`)})),t.subscriptions.push(h.commands.registerCommand("secret-leak-detector.uninstallGitHook",async()=>{if((h.workspace.workspaceFolders||[]).length===0){h.window.showWarningMessage("Please open a Git repository in VS Code before uninstalling the pre-commit hook.");return}let p=await r.getHookPath(),v=await r.uninstallPreCommitHook();if(v.success){try{let m=Z.join(t.globalStorageUri.fsPath,"installed-hooks.json");if(N.existsSync(m)){let S=JSON.parse(N.readFileSync(m,"utf8"));if(Array.isArray(S)){let b=S.filter(A=>A!==p);N.writeFileSync(m,JSON.stringify(b,null,2),"utf8")}}Be(p)}catch(m){B.appendLine(`[Registry] Error updating hooks record: ${m?.message||m}`)}h.window.showInformationMessage(`\u{1F6E1}\uFE0F ${v.message}`)}else h.window.showErrorMessage(`Failed to uninstall hook: ${v.message}`)})),t.subscriptions.push(h.commands.registerCommand("secret-leak-detector.ignoreFinding",async d=>{let p=d;if(!p){let b=e.getAllFindings();if(b.length===0){h.window.showInformationMessage("No active findings to ignore.");return}let A=await h.window.showQuickPick(b.map(k=>({label:`${k.type} (${k.file}:${k.line})`,description:k.redactedSecret,id:k.id})),{placeHolder:"Select a finding to ignore (suppress as false-positive)"});if(!A)return;p=A.id}e.ignoreFinding(p);let v=e.getIgnoredFindings();await t.workspaceState.update("ignoredFindings",v);let S=e.getAllFindings().find(b=>b.id===p);if(S){let b=t.workspaceState.get("ignoredFindingsMeta",{});b[p]={type:S.type,file:S.file,line:S.line,secret:S.redactedSecret},await t.workspaceState.update("ignoredFindingsMeta",b)}h.window.showInformationMessage("\u{1F6E1}\uFE0F Finding marked as false-positive and suppressed.")})),t.subscriptions.push(h.commands.registerCommand("secret-leak-detector.unignoreFinding",async()=>{let d=e.getIgnoredFindings();if(d.length===0){h.window.showInformationMessage("No suppressed findings to restore.");return}let p=t.workspaceState.get("ignoredFindingsMeta",{}),v=d.map(b=>{let A=p[b];return{label:A?`${A.type} (${A.secret})`:b,description:A?`${Z.basename(A.file)}:${A.line}`:void 0,detail:A?A.file:b,id:b}}),m=await h.window.showQuickPick(v,{placeHolder:"Select a suppressed finding to restore"});if(!m)return;let S=d.filter(b=>b!==m.id);e.setIgnoredFindings(S),await t.workspaceState.update("ignoredFindings",S),delete p[m.id],await t.workspaceState.update("ignoredFindingsMeta",p),h.window.activeTextEditor&&e.scanDocument(h.window.activeTextEditor.document),h.window.showInformationMessage(`\u{1F6E1}\uFE0F Restored finding '${m.label}'.`)})),t.subscriptions.push(h.commands.registerCommand("secret-leak-detector.remediateFinding",async(d,p,v)=>{await fe.executeRemediation(d,p,v)})),t.subscriptions.push(h.commands.registerCommand("secret-leak-detector.clearFindings",()=>{e.clear(),h.window.showInformationMessage("Secret Leak Detector: All findings cleared.")})),r.isGitRepo().then(d=>{i.update(0,d)})}function Tn(){for(let t of Ee.values())clearTimeout(t);Ee.clear()}0&&(module.exports={activate,deactivate});
