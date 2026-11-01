"use strict";var _t=Object.create;var be=Object.defineProperty;var Tt=Object.getOwnPropertyDescriptor;var Pt=Object.getOwnPropertyNames;var Ft=Object.getPrototypeOf,Dt=Object.prototype.hasOwnProperty;var Lt=(t,e)=>{for(var n in e)be(t,n,{get:e[n],enumerable:!0})},Ge=(t,e,n,i)=>{if(e&&typeof e=="object"||typeof e=="function")for(let s of Pt(e))!Dt.call(t,s)&&s!==n&&be(t,s,{get:()=>e[s],enumerable:!(i=Tt(e,s))||i.enumerable});return t};var P=(t,e,n)=>(n=t!=null?_t(Ft(t)):{},Ge(e||!t||!t.__esModule?be(n,"default",{value:t,enumerable:!0}):n,t)),Nt=t=>Ge(be({},"__esModule",{value:!0}),t);var cn={};Lt(cn,{activate:()=>rn,deactivate:()=>an});module.exports=Nt(cn);var f=P(require("vscode")),q=P(require("path")),B=P(require("fs"));var R=P(require("vscode"));var oe=P(require("path")),ft=P(require("crypto"));var Ve=[{id:"aws-access-key",name:"AWS Access Key ID",provider:"Amazon Web Services",pattern:/\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b/g,baseConfidence:98,baseRiskWeight:95,signals:["AWS IAM standard 20-character key prefix (AKIA/ASIA/ABIA/ACCA)","Deterministic uppercase alphanumeric structure","Direct cloud resource control & hijacking capability"],suggestedEnvName:()=>"AWS_ACCESS_KEY_ID",remediationInstructions:["Revoke the exposed Access Key ID immediately in AWS IAM Management Console.","Check AWS CloudTrail logs for unauthorized API calls originated by this key.","Transition to IAM Roles for Amazon EC2 or AWS IAM Identity Center (SSO).","Never store access keys in source code; use AWS_ACCESS_KEY_ID environment variable."]},{id:"aws-secret-key",name:"AWS Secret Access Key",provider:"Amazon Web Services",pattern:/["']?(?:aws_secret_access_key|aws_secret_key|secret_access_key)["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?(?:[\s\r\n;,)]|$)/gi,baseConfidence:94,baseRiskWeight:95,minEntropy:4.1,signals:["Contextual AWS credential parameter match","High-entropy 40-character Base64 payload","Pairs with AWS Access Key for root/IAM API authentication"],suggestedEnvName:()=>"AWS_SECRET_ACCESS_KEY",remediationInstructions:["Rotate the key pair immediately in the AWS IAM Console.","Audit AWS KMS and S3 bucket accesses during exposure window.","Store secrets in AWS Secrets Manager or Parameter Store."]},{id:"github-pat",name:"GitHub Personal Access Token",provider:"GitHub",pattern:/\b(gh[pousr]_[A-Za-z0-9_]{36,255}|github_pat_[A-Za-z0-9_]{82})\b/g,baseConfidence:99,baseRiskWeight:95,signals:["Official GitHub token format prefix (ghp_, gho_, ghu_, ghs_, github_pat_)","Deterministic token structure and length","Permits repository code modification, workflow execution, or release poisoning"],suggestedEnvName:()=>"GITHUB_TOKEN",remediationInstructions:["Revoke token immediately at https://github.com/settings/tokens.","Check GitHub Security Audit Log for unauthorized repository clones or writes.","Use GitHub fine-grained PATs with scoped repository permissions.","Use GitHub Actions secrets rather than personal tokens for CI/CD."]},{id:"google-api-key",name:"Google Cloud / Gemini API Key",provider:"Google Cloud",pattern:/\b(AIza[0-9A-Za-z_-]{34,35})\b/g,baseConfidence:96,baseRiskWeight:90,minEntropy:3.5,signals:["Google standard AIza service key signature","Fixed 39-character alphanumeric structure","Access to Google Cloud Platform APIs and billing services"],suggestedEnvName:()=>"GEMINI_API_KEY",remediationInstructions:["Restrict or delete the API key in Google Cloud Console Credentials page.","Apply API restrictions (e.g. restrict solely to Generative Language API).","Apply HTTP referrer or IP address restrictions.","Store in GEMINI_API_KEY environment variable."]},{id:"google-oauth-token",name:"Google OAuth Access Token",provider:"Google Cloud",pattern:/\b(ya29\.[0-9a-zA-Z_-]{50,150})\b/g,baseConfidence:98,baseRiskWeight:92,minEntropy:4,signals:["Google OAuth bearer access token prefix (ya29.)","Direct user account delegation & Cloud Platform API access"],suggestedEnvName:()=>"GOOGLE_OAUTH_TOKEN",remediationInstructions:["Revoke token via Google Cloud IAM or OAuth2 token revocation endpoint.","Store OAuth refresh tokens securely in credential vaults."]},{id:"openai-api-key",name:"OpenAI API Key",provider:"OpenAI",pattern:/\b(sk-(?:proj|admin|svcacct)-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{20,48})\b/g,baseConfidence:97,baseRiskWeight:92,minEntropy:4,signals:["OpenAI official secret prefix (sk-proj- or sk-)","High Shannon entropy key payload","Direct account credit exhaustion and model theft risk"],suggestedEnvName:()=>"OPENAI_API_KEY",remediationInstructions:["Revoke key at https://platform.openai.com/api-keys.","Verify credit consumption in OpenAI usage dashboard.","Inject credentials using OPENAI_API_KEY environment variable."]},{id:"anthropic-api-key",name:"Anthropic Claude API Key",provider:"Anthropic",pattern:/\b(sk-ant-[A-Za-z0-9_-]{30,})\b/g,baseConfidence:98,baseRiskWeight:92,minEntropy:3.8,signals:["Anthropic official secret token signature (sk-ant-)","High entropy cryptographic token payload","Direct Claude model API billing access"],suggestedEnvName:()=>"ANTHROPIC_API_KEY",remediationInstructions:["Revoke the API key in Anthropic Console.","Generate replacement key with spend limit configured.","Inject via ANTHROPIC_API_KEY environment variable."]},{id:"huggingface-token",name:"Hugging Face Access Token",provider:"Hugging Face",pattern:/\b(hf_[A-Za-z0-9]{34})\b/g,baseConfidence:98,baseRiskWeight:88,minEntropy:3.8,signals:["Hugging Face user access token format (hf_ prefix + 34 chars)","Grants access to gated AI models, private repositories, and inference endpoints"],suggestedEnvName:()=>"HF_TOKEN",remediationInstructions:["Revoke token immediately at https://huggingface.co/settings/tokens.","Audit access logs for unauthorized model downloads.","Inject credentials using the HF_TOKEN environment variable."]},{id:"stripe-secret-key",name:"Stripe Secret Key",provider:"Stripe",pattern:/\b((?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,100})\b/g,baseConfidence:97,baseRiskWeight:96,signals:["Stripe signature prefix (sk_live / rk_live / sk_test)","Financial transaction and customer credit card access","High financial liability and compliance breach"],suggestedEnvName:()=>"STRIPE_SECRET_KEY",remediationInstructions:["Roll API key immediately in Stripe Dashboard > Developers > API keys.","Audit recent transactions and payout bank account modifications.","Never bundle Stripe secret keys in frontend or mobile client builds."]},{id:"slack-bot-token",name:"Slack OAuth / Bot Token",provider:"Slack",pattern:/\b(xox[baprs]-[0-9A-Za-z-]{10,72})\b/g,baseConfidence:95,baseRiskWeight:82,signals:["Slack OAuth bot/user prefix (xoxb/xoxp/xoxa)","Internal company communications and workspace access"],suggestedEnvName:()=>"SLACK_BOT_TOKEN",remediationInstructions:["Revoke token in api.slack.com/apps.","Re-install app with minimal necessary OAuth scopes."]},{id:"slack-webhook",name:"Slack Incoming Webhook URL",provider:"Slack",pattern:/(https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9_]{8,12}\/B[A-Z0-9_]{8,12}\/[A-Za-z0-9_]{24})/g,baseConfidence:98,baseRiskWeight:78,signals:["Slack Incoming Webhook URL structure","Enables unauthorized message spoofing and channel phishing"],suggestedEnvName:()=>"SLACK_WEBHOOK_URL",remediationInstructions:["Delete the exposed webhook URL in Slack App settings.","Generate a new webhook URL and store in SLACK_WEBHOOK_URL."]},{id:"azure-storage-key",name:"Azure Shared Storage Key",provider:"Microsoft Azure",pattern:/["']?(?:AccountKey|azure_secret|azure_key)["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{86,88}==)(?:["';,\s\r\n)]|$)/gi,baseConfidence:93,baseRiskWeight:90,minEntropy:4.2,signals:["Azure storage account key signature (86-88 chars base64 with == padding)","Full administrative access to Azure Blob/Queue/Table storage"],suggestedEnvName:()=>"AZURE_STORAGE_KEY",remediationInstructions:["Regenerate storage key in Azure Portal.","Adopt Azure Managed Identity or Microsoft Entra ID authentication instead."]},{id:"azure-ad-client-secret",name:"Azure Active Directory Client Secret",provider:"Microsoft Azure",pattern:/["']?(?:azure[_-]?(?:client|ad|app)?[_-]?secret|client[_-]?secret)\s*[:=]\s*["']?([a-zA-Z0-9_~.-]{34,44})["']?(?:[\s\r\n;,)]|$)/gi,baseConfidence:90,baseRiskWeight:90,minEntropy:3.8,signals:["Azure AD / Entra ID client secret assignment pattern","Application impersonation and tenant directory access"],suggestedEnvName:()=>"AZURE_CLIENT_SECRET",remediationInstructions:["Revoke and rotate the client secret in Azure App Registrations portal.","Migrate to Managed Identity or Federated Credentials where possible."]},{id:"discord-bot-token",name:"Discord Bot Token",provider:"Discord",pattern:/\b([M-Z][A-Za-z0-9]{23,27}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,38})\b/g,baseConfidence:98,baseRiskWeight:88,signals:["Official Discord bot token format (ID.HMAC.Signature)","Complete bot control, server membership manipulation, and message reading"],suggestedEnvName:()=>"DISCORD_BOT_TOKEN",remediationInstructions:["Reset token in Discord Developer Portal > Bot > Reset Token.","Store in DISCORD_BOT_TOKEN environment variable."]},{id:"telegram-bot-token",name:"Telegram Bot Token",provider:"Telegram",pattern:/\b([0-9]{8,10}:[a-zA-Z0-9_-]{35})\b/g,baseConfidence:96,baseRiskWeight:85,signals:["Telegram Bot API token format (Numeric ID : 35-character secret)","Direct control of Telegram bot communications and webhooks"],suggestedEnvName:()=>"TELEGRAM_BOT_TOKEN",remediationInstructions:["Revoke and reissue the token using Telegram @BotFather (/revoke).","Store in TELEGRAM_BOT_TOKEN environment variable."]},{id:"pypi-api-token",name:"PyPI API Token",provider:"PyPI",pattern:/\b(pypi-[A-Za-z0-9_-]{50,150})\b/g,baseConfidence:99,baseRiskWeight:92,signals:["Official PyPI package index upload token prefix (pypi-)","Supply chain compromise and malicious Python package publication risk"],suggestedEnvName:()=>"PYPI_TOKEN",remediationInstructions:["Revoke the token immediately at https://pypi.org/manage/account/tokens/.","Inspect published package versions for tampering."]},{id:"shopify-access-token",name:"Shopify Admin / Storefront Access Token",provider:"Shopify",pattern:/\b(shp(?:at|ca|pa)_[a-fA-F0-9]{32})\b/g,baseConfidence:98,baseRiskWeight:92,signals:["Official Shopify access token prefix (shpat_, shpca_, shppa_)","E-commerce store data, customer orders, and payment configuration access"],suggestedEnvName:()=>"SHOPIFY_API_KEY",remediationInstructions:["Revoke the token in Shopify Admin > Apps and sales channels.","Audit store access and customer data logs."]},{id:"digitalocean-pat",name:"DigitalOcean Personal Access Token",provider:"DigitalOcean",pattern:/\b(dop_v1_[a-f0-9]{64})\b/g,baseConfidence:99,baseRiskWeight:92,signals:["Official DigitalOcean v1 token format (dop_v1_ prefix + 64 hex characters)","Droplet creation, destruction, and Cloud infrastructure control"],suggestedEnvName:()=>"DIGITALOCEAN_TOKEN",remediationInstructions:["Revoke the token in DigitalOcean Control Panel > API > Tokens.","Check active Droplets and firewall configurations for unauthorized changes."]},{id:"mailgun-api-key",name:"Mailgun Private API Key",provider:"Mailgun",pattern:/\b(key-[0-9a-zA-Z]{32})\b/g,baseConfidence:96,baseRiskWeight:85,signals:["Mailgun standard private API key signature (key- + 32 chars)","Bulk email dispatch and communication channel spoofing"],suggestedEnvName:()=>"MAILGUN_API_KEY",remediationInstructions:["Rotate key in Mailgun Dashboard > API Security.","Store in MAILGUN_API_KEY environment variable."]},{id:"square-access-token",name:"Square Access Token",provider:"Square",pattern:/\b(sq0atp-[0-9A-Za-z_-]{22}|sq0csp-[0-9A-Za-z_-]{43}|EAAA[a-zA-Z0-9_-]{60})\b/g,baseConfidence:97,baseRiskWeight:94,signals:["Square OAuth / production access token prefix (sq0atp-, sq0csp-, EAAA)","Payment processing, merchant account, and customer financial data access"],suggestedEnvName:()=>"SQUARE_ACCESS_TOKEN",remediationInstructions:["Revoke token in Square Developer Dashboard > OAuth settings.","Audit payment ledger and API access history."]},{id:"private-key",name:"Cryptographic Private Key (PEM)",provider:"Cryptography",pattern:/(-----BEGIN (?:[A-Z0-9_-]+ )*PRIVATE KEY(?: BLOCK)?-----(?:(?!-----BEGIN)[\s\S]){1,8192}?-----END (?:[A-Z0-9_-]+ )*PRIVATE KEY(?: BLOCK)?-----)/g,baseConfidence:100,baseRiskWeight:100,signals:["Standard PEM container header and footer","Unencrypted cryptographic private key","Total server impersonation, SSH compromise, or TLS decryption risk"],suggestedEnvName:()=>"PRIVATE_KEY_PATH",remediationInstructions:["Immediately decommission this private key pair.","Remove public key counterpart from all servers authorized_keys.","Never commit private keys to version control; use SSH agents or secret vaults."]},{id:"database-url",name:"Database Connection String with Credentials",provider:"Database",pattern:/\b((?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis):\/\/[^:\s'"@]+:([^@\s'"]+)@([a-zA-Z0-9_.-]+(?::[0-9]+)?(?:\/[^\s'"`;]*)?))/gi,baseConfidence:92,baseRiskWeight:88,minEntropy:3.2,signals:["Database connection URL containing embedded user:password credentials","Direct data exfiltration, deletion, or ransomware risk"],suggestedEnvName:()=>"DATABASE_URL",remediationInstructions:["Rotate the database user password immediately on the database server.","Migrate connection string to DATABASE_URL environment variable.","Enable SSL/TLS requirement and VPC network access controls."]},{id:"url-credentials",name:"URL with Embedded Credentials",provider:"Generic Credential",pattern:/\b(https?:\/\/[^:\s'"\/?#@]+:([^@\s'"\/?#]+)@([a-zA-Z0-9_.-]+(?::[0-9]+)?(?:\/[^\s'"`;]*)?))/gi,baseConfidence:90,baseRiskWeight:85,minEntropy:3,signals:["HTTP/HTTPS URL containing embedded user:password or user:token credentials","Authentication credential transmission in URL plain text"],suggestedEnvName:()=>"API_ENDPOINT_URL",remediationInstructions:["Remove credentials from URL; pass authentication in Authorization headers.","Rotate exposed password or access token immediately."]},{id:"bearer-token",name:"Authorization Bearer Token",provider:"Auth / Identity",pattern:/(?:Authorization|auth)\s*[:=]\s*["']?Bearer\s+([A-Za-z0-9_.~+/-]{20,255})["']?/gi,baseConfidence:92,baseRiskWeight:85,minEntropy:3.5,signals:["HTTP Authorization header with static Bearer token literal","API session impersonation and service authentication bypass"],suggestedEnvName:()=>"AUTH_TOKEN",remediationInstructions:["Revoke the exposed bearer token.","Inject bearer tokens dynamically from environment variables."]},{id:"jwt-token",name:"JSON Web Token (JWT)",provider:"Auth / Identity",pattern:/\b(ey[A-Za-z0-9_-]{15,}\.ey[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{10,})\b/g,baseConfidence:88,baseRiskWeight:75,minEntropy:4.1,signals:["Header.Payload.Signature Base64 tripartite JWT structure","Authentication session hijacking and privilege escalation"],suggestedEnvName:t=>t?.toUpperCase()||"AUTH_TOKEN",remediationInstructions:["Invalidate active sessions / revoke refresh token family in identity provider.","Never hardcode tokens in client or backend source repositories."]},{id:"gitlab-pat",name:"GitLab Personal Access Token",provider:"GitLab",pattern:/\b(glpat-[0-9a-zA-Z_-]{20,40})\b/g,baseConfidence:98,baseRiskWeight:90,signals:["GitLab personal access token prefix (glpat-)","Repository read/write and CI/CD control"],suggestedEnvName:()=>"GITLAB_TOKEN",remediationInstructions:["Revoke token in GitLab User Settings > Access Tokens.","Store in GITLAB_TOKEN environment variable."]},{id:"npm-access-token",name:"npm Access Token",provider:"npm",pattern:/\b(npm_[A-Za-z0-9]{36})\b/g,baseConfidence:99,baseRiskWeight:92,signals:["npm official access token prefix (npm_)","Package publication and account takeover capability"],suggestedEnvName:()=>"NPM_TOKEN",remediationInstructions:["Revoke token immediately at https://www.npmjs.com/settings/tokens.","Store in NPM_TOKEN environment variable."]},{id:"sendgrid-api-key",name:"SendGrid API Key",provider:"SendGrid",pattern:/\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b/g,baseConfidence:99,baseRiskWeight:85,signals:["SendGrid standard tripartite API key (SG.<22>.<43>)","Email spoofing and communication channel hijacking risk"],suggestedEnvName:()=>"SENDGRID_API_KEY",remediationInstructions:["Revoke key in SendGrid dashboard Settings > API Keys.","Store in SENDGRID_API_KEY environment variable."]},{id:"twilio-api-key",name:"Twilio Auth Token / API Secret",provider:"Twilio",pattern:/\b(SK[0-9a-fA-F]{32})\b|["']?(?:twilio[a-z0-9_-]*(?:auth_?token|api_?secret|secret)|(?:auth_?token|api_?secret))\s*[:=]\s*["']?([0-9a-fA-F]{32})["']?(?:[\s\r\n;,)]|$)/gi,baseConfidence:95,baseRiskWeight:90,minEntropy:3.5,signals:["Twilio Auth Token, API Key SID (SK...), or API Secret assignment","32-character hexadecimal secret token","Telephony API and SMS billing access"],suggestedEnvName:()=>"TWILIO_AUTH_TOKEN",remediationInstructions:["Rotate token in Twilio Console.","Store in TWILIO_AUTH_TOKEN environment variable."]},{id:"password-assignment",name:"Password in Source Code",provider:"Generic Credential",pattern:/["']?(?:password|passwd|pwd|db_password|db_pass)["']?\s*[:=]\s*["']?(?!(?:password|passwordRequired|required|required_field|true|false|null|undefined|string|default|changeme|placeholder|example|admin|test)\b)([^"'\r\n\s#;,]{8,64})["']?/gi,baseConfidence:82,baseRiskWeight:80,minEntropy:2.8,signals:["Hard-coded password assignment in code, .env, or YAML","Credential exposure in plain text"],suggestedEnvName:()=>"PASSWORD",remediationInstructions:["Rotate password immediately.","Store password in an environment variable or secrets manager.","Never commit plain passwords to version control."]},{id:"generic-api-key",name:"Generic API Secret Assignment",provider:"Generic Credential",pattern:/["']?(?:api_?key|secret_?key|auth_?token|client_?secret|access_?token|private_?key|jwt_?secret)["']?\s*[:=]\s*["']?(?!(?:process\.env|import\.meta\.env|os\.environ|ENV)\b)([A-Za-z0-9_.~/+=]{20,90})["']?(?:[\s\r\n;,)]|$)/gi,baseConfidence:80,baseRiskWeight:70,minEntropy:3.5,signals:["Sensitive identifier keyword assignment in code, .env, or YAML","High Shannon entropy string literal"],suggestedEnvName:t=>t?t.toUpperCase():"API_KEY",remediationInstructions:["Identify corresponding API provider and rotate credential.","Migrate credential to local .env file (ensure .env is in .gitignore)."]}];var G=P(require("path")),Ot=[/api[_-]?key/i,/secret[_-]?key/i,/access[_-]?token/i,/auth[_-]?token/i,/private[_-]?key/i,/client[_-]?secret/i,/password/i,/credential/i,/session[_-]?token/i,/bearer/i,/aws[_-]?(?:access|secret)/i,/stripe[_-]?(?:secret|key)/i,/github[_-]?(?:token|pat)/i,/slack[_-]?token/i,/db[_-]?pass(?:word)?/i],$t=[/placeholder/i,/mock/i,/dummy/i,/fake/i,/sample/i,/test[_-]?(?:key|token|id)/i,/demo/i,/insert[_-]?here/i];function Mt(t,e){if(e){let n=G.relative(e,t);if(!n.startsWith("..")&&!G.isAbsolute(n))return n.replace(/\\/g,"/")}return G.isAbsolute(t)?G.basename(t):t.replace(/\\/g,"/")}function Ue(t,e){let n=Mt(t,e).toLowerCase(),i=G.basename(t).toLowerCase(),s=G.extname(t).toLowerCase(),r=/(?:^|\/)(?:tests?|specs?|__tests__|__mocks__|fixtures|mocks)\//i.test(n)||/[._-](?:test|spec)\.[a-z0-9]+$/i.test(i)||/^(?:test|spec)\.[a-z0-9]+$/i.test(i),o=/(?:^|\/)(?:docs|doc|documentation|tutorials|guides)\/|readme\.md|contributing\.md|changelog\.md/i.test(n),a=/(?:^|\/)(?:example|sample|\.example|\.sample)/i.test(n)||/[._-](?:example|sample)\.[a-z0-9]+$/i.test(i),d=/^\.env(?:\.[a-z0-9]+)?$/.test(i)||/(?:^|\/)(?:config|settings|k8s|helm|deploy|tfvars)\//i.test(n)||/(?:^|[._-])(?:config|settings|secret|credential|database|deploy)\.[a-z0-9]+$/i.test(i)||[".env",".yaml",".yml",".json",".toml",".ini",".tf"].includes(s),p=/^\.env/.test(i)||/(?:secret|credential|id_rsa|private_key|keypair|auth_config)/i.test(i);return{fileExtension:s,isConfig:d,isTest:r,isDoc:o,isSensitiveName:p,isExampleOrSample:a}}function Pe(t,e){let n=t[e]||"",i=[];for(let h=Math.max(0,e-3);h<e;h++)i.push(t[h]);let s=[];for(let h=e+1;h<Math.min(t.length,e+4);h++)s.push(t[h]);let r,o=n.match(/(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*[:=]/),a=n.match(/["']?([a-zA-Z0-9_$-]+)["']?\s*[:=]/);o?r=o[1]:a&&(r=a[1]);let d=r?Ot.some(h=>h.test(r)):!1,p=r?$t.some(h=>h.test(r)):!1,g=/[:=]/.test(n),c=/(?:process\.env|os\.environ|dotenv|config|getenv)/i.test(n),l=/(?:authorization|bearer|x-api-key)/i.test(n),u=/^\s*(?:\/\/|#|\/\*|\*|--)/.test(n);return{inferredVariable:r,isSensitiveIdentifier:d,isBenignIdentifier:p,isAssignment:g,isEnvOrConfigAccess:c,isHeaderOrBearer:l,isInComment:u,surroundingBefore:i,matchedLine:n,surroundingAfter:s}}var ye=/(?:api_?key|secret|token|password|auth|credential|access_?key|private_?key)/i,je=/(?:console\.(?:log|warn|error|info|debug)|logger\.|print\(|logging\.)/i,ke=null;try{ke=require("typescript")}catch{ke=null}function Fe(t,e,n){let i=t[e]||"";if(ke&&(!n||/\.[jt]sx?$|\.m[jt]s$|\.c[jt]s$/i.test(n))){let r,o;if(t.length>60){let d=Math.max(0,e-30),p=Math.min(t.length,e+30);r=t.slice(d,p).join(`
`),o=e-d}else r=t.join(`
`),o=e;let a=Bt(r,o);if(a)return a}return Wt(i)}function Bt(t,e){try{let p=function(g){if(!d&&!(g.pos>a||g.end<o)&&(i.forEachChild(g,p),!d)){if(g.kind===i.SyntaxKind.BinaryExpression&&(g.operatorToken.kind===i.SyntaxKind.BarBarToken||g.operatorToken.kind===i.SyntaxKind.QuestionQuestionToken)){let c=g.left.getText(s);if(c.includes("process.env")||c.includes("env")||c.toLowerCase().includes("key")){d={variablePath:c,isSensitiveProperty:ye.test(c),isEnvFallback:!0,isAuthorizationHeader:!1,isLoggingCall:!1,scopeType:"ENV_FALLBACK"};return}}if(g.kind===i.SyntaxKind.PropertyAssignment){let c=g.name.getText(s),l=c,u=g.parent;for(;u;)u.kind===i.SyntaxKind.PropertyAssignment&&u.name?l=`${u.name.getText(s)}.${l}`:u.kind===i.SyntaxKind.VariableDeclaration&&u.name&&(l=`${u.name.getText(s)}.${l}`),u=u.parent;let h=ye.test(l),v=/authorization|bearer|x-api-key/i.test(c);d={variablePath:l,isSensitiveProperty:h,isEnvFallback:!1,isAuthorizationHeader:v,isLoggingCall:!1,scopeType:v?"HEADER":"OBJECT_PROPERTY"};return}if(g.kind===i.SyntaxKind.CallExpression){let c=g.expression.getText(s);if(je.test(c)){d={variablePath:c,isSensitiveProperty:!1,isEnvFallback:!1,isAuthorizationHeader:!1,isLoggingCall:!0,scopeType:"FUNCTION_ARG"};return}}if(g.kind===i.SyntaxKind.VariableDeclaration){let c=g.name.getText(s);d={variablePath:c,isSensitiveProperty:ye.test(c),isEnvFallback:!1,isAuthorizationHeader:!1,isLoggingCall:!1,scopeType:"VARIABLE_DECLARATION"};return}}};var n=p;let i=ke,s=i.createSourceFile("eval_target.tsx",t,i.ScriptTarget.Latest,!0,i.ScriptKind.TSX),r=s.getLineStarts();if(e>=r.length)return null;let o=r[e],a=e+1<r.length?r[e+1]-1:t.length,d=null;return p(s),d}catch{return null}}function Wt(t){let e=je.test(t),n=/(?:process\.env\.[A-Za-z0-9_]+|os\.(?:getenv|environ\.get)\([^)]+\))\s*(?:\|\||\?\?)\s*["'][^"']+["']/.test(t),i=/(?:authorization|x-api-key|bearer)\s*[:=]/i.test(t),s=t.match(/([a-zA-Z0-9_$.]+)\s*[:=]\s*["'][^"']+["']/)||t.match(/["']([a-zA-Z0-9_.]+)["']\s*:\s*["'][^"']+["']/),r,o=!1;s&&(r=s[1],o=ye.test(r));let a="UNKNOWN";return n?a="ENV_FALLBACK":i?a="HEADER":r&&r.includes(".")?a="OBJECT_PROPERTY":r?a="VARIABLE_DECLARATION":e&&(a="FUNCTION_ARG"),{variablePath:r,isSensitiveProperty:o,isEnvFallback:n,isAuthorizationHeader:i,isLoggingCall:e,scopeType:a}}function le(t){if(!t||t.length===0)return 0;let e={};for(let s of t)e[s]=(e[s]||0)+1;let n=0,i=t.length;for(let s in e){let r=e[s]/i;n-=r*Math.log2(r)}return Math.round(n*100)/100}function De(t){return/^[0-9a-fA-F]+$/.test(t)?{setName:"HEX",baseSize:16}:/^[A-Za-z0-9+/=_-]+$/.test(t)?{setName:"BASE64",baseSize:64}:/^[A-Za-z0-9]+$/.test(t)?{setName:"ALPHANUMERIC",baseSize:62}:/^[\x20-\x7E]+$/.test(t)?{setName:"ASCII_PRINTABLE",baseSize:95}:{setName:"SPECIAL",baseSize:128}}function Ze(t){if(!t||t.length===0)return 0;let e=le(t),{baseSize:n}=De(t),i=Math.log2(n);if(i<=0)return 0;let s=Math.min(1,e/i);return Math.round(s*100)/100}var zt=[/\bplaceholder\b/i,/\byour[_-]?(?:api)?[_-]?key\b/i,/\byour[_-]?secret\b/i,/\byour[_-]?token\b/i,/\binsert[_-]?here\b/i,/\breplace[_-]?me\b/i,/\benter[_-]?your\b/i,/\bchange[_-]?me\b/i,/\bdummy\b/i,/\bfake[_-]?token\b/i,/xxxx+/i,/\btest[_-]?value\b/i,/AKIAIOSFODNN7EXAMPLE/i,/wJalrXUtnFEMI\/K7MDENG\/bPxRfiCYEXAMPLEKEY/i,/^123456789[0-9]*$/,/^abcdef[a-z0-9]*$/i,/00000000[0-9]*/,/sk_live_example/i,/ghp_example/i,/:\/\/[^:]+:(?:password|secret|changeme|pass|admin|test|postgres|root)@(?:localhost|127\.0\.0\.1)(?::\d+)?\b/i,/:\/\/(?:postgres|root):(postgres|root)@(?:localhost|127\.0\.0\.1)(?::\d+)?\b/i],Ht=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,Kt=/^(?:mock|dummy|placeholder|fake|sample)_(?:key|token|secret|password|pwd|cred)$/i;function Ye(t,e,n){if(/(?:process\.env|import\.meta\.env|os\.environ|ENV[\[\.])/.test(t))return{isFalsePositive:!0,reason:"Environment variable lookup expression, not a hard-coded credential literal",confidencePenalty:100};if(/^(?:passwordRequired|required_field|required|optional|placeholder|changeme|default|test|dummy|example|string|undefined|null)$/i.test(t))return{isFalsePositive:!0,reason:"Common non-secret schema or form attribute value",confidencePenalty:100};for(let s of zt)if(s.test(t))return{isFalsePositive:!0,reason:`Matched known documentation/placeholder pattern: ${s.source}`,confidencePenalty:100};if(e&&Kt.test(e)&&!(t.startsWith("AKIA")||t.startsWith("ASIA")||t.startsWith("ghp_")||t.startsWith("gho_")||t.startsWith("ghu_")||t.startsWith("ghs_")||t.startsWith("ghr_")||t.startsWith("github_pat_")||t.startsWith("glpat-")||t.startsWith("sk_live_")||t.startsWith("rk_live_")||t.startsWith("xoxb-")||t.startsWith("xoxp-")||t.startsWith("xoxa-")||t.startsWith("xoxr-")||t.startsWith("pypi-")||t.startsWith("dop_v1_")||t.startsWith("shpat_")||t.startsWith("shpca_")||t.startsWith("shppa_")||t.startsWith("ya29.")||t.startsWith("key-")||t.startsWith("sq0atp-")||t.startsWith("sq0csp-")||/^SK[0-9a-fA-F]{32}$/.test(t)||t.includes("-----BEGIN")||t.length>=14&&le(t)>=3.6))return{isFalsePositive:!0,reason:`Variable identifier indicates placeholder: ${e}`,confidencePenalty:100};let i=new Set(t.split("")).size;if(t.length>=10&&i<=3)return{isFalsePositive:!0,reason:"Low character diversity (repetitive filler characters)",confidencePenalty:95};if(Ht.test(t)&&!e?.match(/secret|token|api_?key/i))return{isFalsePositive:!0,reason:"Standard UUID identifier without credential context",confidencePenalty:90};if(n){let s=/(?:docs|documentation|tutorials|guides)\/|readme\.md/i.test(n);if(/(?:example|sample|\.example|\.sample)/i.test(n)&&/example|your_/i.test(t))return{isFalsePositive:!0,reason:"Sample configuration value inside template/example file",confidencePenalty:90};if(s&&!t.startsWith("ghp_")&&!t.startsWith("AKIA"))return{isFalsePositive:!1,confidencePenalty:25}}return{isFalsePositive:!1,confidencePenalty:0}}function qe(t){if(!/^(AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}$/.test(t))return{isValid:!1,confidenceBonus:0,reason:"Invalid AWS key length or character set"};let e=t.substring(0,4);return{isValid:!0,confidenceBonus:10,reason:{AKIA:"Standard permanent IAM user access key",ASIA:"Temporary STS session access key",ABIA:"AWS Backup access key",ACCA:"AWS CodeCommit access key"}[e]||"Valid AWS Access Key ID structure"}}function Je(t){let e=/^sk_live_[0-9a-zA-Z]{24,100}$/.test(t)||/^rk_live_[0-9a-zA-Z]{24,100}$/.test(t),n=/^sk_test_[0-9a-zA-Z]{24,100}$/.test(t)||/^rk_test_[0-9a-zA-Z]{24,100}$/.test(t);return!e&&!n?{isValid:!1,confidenceBonus:0,reason:"Does not match official Stripe secret key format"}:{isValid:!0,confidenceBonus:e?12:5,reason:e?"Production live Stripe Secret Key":"Stripe Test API key"}}function Xe(t){return/^ghp_[A-Za-z0-9_]{36}$/.test(t)?{isValid:!0,confidenceBonus:12,reason:"GitHub Personal Access Token (Classic)"}:/^gho_[A-Za-z0-9_]{36}$/.test(t)?{isValid:!0,confidenceBonus:10,reason:"GitHub OAuth Access Token"}:/^ghs_[A-Za-z0-9_]{36}$/.test(t)?{isValid:!0,confidenceBonus:10,reason:"GitHub Server-to-server token"}:/^github_pat_[A-Za-z0-9_]{82}$/.test(t)?{isValid:!0,confidenceBonus:15,reason:"GitHub Fine-Grained Personal Access Token"}:{isValid:!1,confidenceBonus:0,reason:"Invalid GitHub token prefix or length"}}function Qe(t){let e=t.split(".");if(e.length!==3)return{isValid:!1,confidenceBonus:0,reason:"Not a 3-part dot-separated JWT"};try{let n=Buffer.from(e[0],"base64url").toString("utf8"),i=JSON.parse(n);if(i&&typeof i=="object"&&i.alg)return{isValid:!0,confidenceBonus:15,reason:`Valid JWT structure with signature algorithm: ${i.alg}`}}catch{}return{isValid:!1,confidenceBonus:0,reason:"Malformed JWT header JSON payload"}}function et(t){try{let e=new URL(t);if(!["postgres:","postgresql:","mysql:","mongodb:","mongodb+srv:","redis:"].includes(e.protocol))return{isValid:!1,confidenceBonus:0,reason:"Unsupported database protocol scheme"};if(e.password&&e.password.length>0)return{isValid:!0,confidenceBonus:12,reason:`Database connection string containing credentials for user '${e.username||"default"}'`}}catch{let e=/^(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis):\/\/[^:\s'"]+:([^\s'"]+)@([a-zA-Z0-9_.-]+(?::[0-9]+)?\/[^\s'"`;]*)/i,n=t.match(e);if(n&&n[1])return{isValid:!0,confidenceBonus:10,reason:"Database connection URI structure matched with embedded password"}}return{isValid:!1,confidenceBonus:0,reason:"Invalid database connection URL structure"}}function tt(t){return/^sk-proj-[A-Za-z0-9_-]{48,}$/.test(t)?{isValid:!0,confidenceBonus:15,reason:"Valid OpenAI Project API Key format"}:/^sk-admin-[A-Za-z0-9_-]{48,}$/.test(t)?{isValid:!0,confidenceBonus:15,reason:"Valid OpenAI Admin/Organization API Key format"}:/^sk-svcacct-[A-Za-z0-9_-]{48,}$/.test(t)?{isValid:!0,confidenceBonus:15,reason:"Valid OpenAI Service Account Key format"}:/^sk-[A-Za-z0-9]{32,48}$/.test(t)?{isValid:!0,confidenceBonus:10,reason:"Valid OpenAI Standard/Legacy API Key format"}:{isValid:!1,confidenceBonus:0,reason:"Invalid OpenAI API key structure"}}function nt(t){return/^sk-ant-[A-Za-z0-9_-]{40,}$/.test(t)?{isValid:!0,confidenceBonus:15,reason:"Valid Anthropic Claude API Key format"}:{isValid:!1,confidenceBonus:0,reason:"Invalid Anthropic API key format"}}function it(t){return/^AIza[0-9A-Za-z_-]{35}$/.test(t)?{isValid:!0,confidenceBonus:12,reason:"Valid Google Cloud / Gemini AIza service key signature"}:{isValid:!1,confidenceBonus:0,reason:"Invalid Google Cloud API key format"}}function st(t){return/^xox[baprs]-[0-9A-Za-z-]{10,72}$/.test(t)?{isValid:!0,confidenceBonus:12,reason:`Valid Slack ${t.startsWith("xoxb")?"Bot Token":t.startsWith("xoxp")?"User Token":"OAuth Token"} signature`}:{isValid:!1,confidenceBonus:0,reason:"Invalid Slack token structure"}}function ot(t){return/^hf_[A-Za-z0-9]{34}$/.test(t)?{isValid:!0,confidenceBonus:12,reason:"Valid Hugging Face User Access Token format"}:{isValid:!1,confidenceBonus:0,reason:"Invalid Hugging Face token structure"}}function rt(t){return/^[A-Za-z0-9/+=]{40}$/.test(t)?{isValid:!0,confidenceBonus:12,reason:"Valid 40-character AWS Secret Access Key Base64 format"}:{isValid:!1,confidenceBonus:0,reason:"Invalid AWS Secret Access Key format"}}function at(t){return/^https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9_]{8,12}\/B[A-Z0-9_]{8,12}\/[A-Za-z0-9_]{24}$/.test(t)?{isValid:!0,confidenceBonus:15,reason:"Valid Slack Incoming Webhook URL structure"}:{isValid:!1,confidenceBonus:0,reason:"Invalid Slack Incoming Webhook URL"}}function ct(t){return/^[A-Za-z0-9/+=]{86,88}==$/.test(t)?{isValid:!0,confidenceBonus:12,reason:"Valid Azure Storage Account Key Base64 format with padding"}:{isValid:!1,confidenceBonus:0,reason:"Invalid Azure Storage Key format"}}function dt(t){let e=/-----BEGIN (?:[A-Z0-9_-]+ )*PRIVATE KEY(?: BLOCK)?-----/.test(t),n=/-----END (?:[A-Z0-9_-]+ )*PRIVATE KEY(?: BLOCK)?-----/.test(t);return e&&n?{isValid:!0,confidenceBonus:20,reason:"Valid Cryptographic Private Key PEM block container"}:{isValid:!1,confidenceBonus:0,reason:"Incomplete or malformed PEM key container"}}function Le(t,e,n,i,s,r){let o=[],a=t.baseConfidence;o.push({signal:"KNOWN_PATTERN_MATCH",description:`Matched recognized credential signature for ${t.provider} (${t.name})`,confidenceImpact:0,details:{ruleId:t.id,provider:t.provider}});let d=le(e),p=Ze(e),{setName:g}=De(e);if(t.minEntropy&&d<t.minEntropy?(a=Math.max(10,a-30),o.push({signal:"LOW_ENTROPY",description:`Low entropy score: ${d} bits/char below minimum threshold of ${t.minEntropy}`,confidenceImpact:-30,details:{shannonEntropy:d,minEntropy:t.minEntropy}})):d>=4.5?(a=Math.min(100,a+5),o.push({signal:"HIGH_ENTROPY",description:`Cryptographic entropy: ${d} bits/char (${g} set), indicates non-human randomness`,confidenceImpact:5,details:{shannonEntropy:d,normalizedEntropy:p,characterSet:g}})):d>=3.4?o.push({signal:"MODERATE_ENTROPY",description:`Moderate entropy: ${d} bits/char (${g} set)`,confidenceImpact:0,details:{shannonEntropy:d,normalizedEntropy:p,characterSet:g}}):(a=Math.max(10,a-15),o.push({signal:"LOW_ENTROPY",description:`Low entropy score: ${d} bits/char (${g} set)`,confidenceImpact:-15,details:{shannonEntropy:d,normalizedEntropy:p,characterSet:g}})),i.isSensitiveIdentifier||r?.isSensitiveProperty){let v=r?.variablePath||i.inferredVariable||"credential";a=Math.min(100,a+10),o.push({signal:"SENSITIVE_IDENTIFIER",description:`Assigned to sensitive identifier / property: '${v}'`,confidenceImpact:10,details:{identifier:v}})}else i.isBenignIdentifier&&(a=Math.max(10,a-25),o.push({signal:"BENIGN_IDENTIFIER",description:`Identifier name indicates mock or sample value: '${i.inferredVariable}'`,confidenceImpact:-25,details:{identifier:i.inferredVariable}}));r?.isEnvFallback&&(a=Math.min(100,a+12),o.push({signal:"ENV_FALLBACK_ASSIGNMENT",description:'Hardcoded literal provided as environment variable fallback (e.g. process.env.KEY || "...")',confidenceImpact:12})),r?.isAuthorizationHeader&&(a=Math.min(100,a+10),o.push({signal:"AUTHORIZATION_HEADER",description:"Passed in HTTP Authorization or Bearer token header context",confidenceImpact:10})),(n.isConfig||n.isSensitiveName)&&(a=Math.min(100,a+8),o.push({signal:"PRODUCTION_CONFIG_FILE",description:`Located in configuration or secret storage file (${n.fileExtension})`,confidenceImpact:8,details:{isConfig:n.isConfig,extension:n.fileExtension}})),n.isTest&&(a=Math.max(20,a-20),o.push({signal:"TEST_FILE_PENALTY",description:"Found inside test/mock directory structure",confidenceImpact:-20})),n.isDoc&&(a=Math.max(20,a-25),o.push({signal:"DOCUMENTATION_PENALTY",description:"Found inside documentation or markdown guide",confidenceImpact:-25}));let c;t.id==="aws-access-key"?c=qe(e):t.id==="aws-secret-key"?c=rt(e):t.id==="stripe-secret-key"?c=Je(e):t.id==="github-pat"?c=Xe(e):t.id==="jwt-token"?c=Qe(e):t.id==="database-url"?c=et(e):t.id==="openai-api-key"?c=tt(e):t.id==="anthropic-api-key"?c=nt(e):t.id==="google-api-key"?c=it(e):t.id==="slack-bot-token"?c=st(e):t.id==="slack-webhook"?c=at(e):t.id==="azure-storage-key"?c=ct(e):t.id==="huggingface-token"?c=ot(e):t.id==="private-key"&&(c=dt(e)),c&&c.isValid&&(a=Math.min(100,a+c.confidenceBonus),o.push({signal:"STRUCTURAL_VALIDATION_PASSED",description:`Structural validation verified: ${c.reason}`,confidenceImpact:c.confidenceBonus}));let l=Ye(e,i.inferredVariable,s);if(l.isFalsePositive)return{confidence:0,evidence:{items:[{signal:"KNOWN_PLACEHOLDER_REJECTED",description:l.reason||"Placeholder value rejected",confidenceImpact:-100}],shannonEntropy:d,normalizedEntropy:p,characterSet:g,surroundingCode:{before:i.surroundingBefore,targetLine:i.matchedLine,after:i.surroundingAfter,inferredVariable:i.inferredVariable},fileContext:{fileExtension:n.fileExtension,isConfig:n.isConfig,isTest:n.isTest,isDoc:n.isDoc,isSensitiveName:n.isSensitiveName,isExampleOrSample:n.isExampleOrSample}},isSuppressed:!0,suppressReason:l.reason};l.confidencePenalty>0&&(a=Math.max(10,a-l.confidencePenalty));let u=Math.max(0,Math.min(100,Math.round(a))),h={items:o,shannonEntropy:d,normalizedEntropy:p,characterSet:g,surroundingCode:{before:i.surroundingBefore,targetLine:i.matchedLine,after:i.surroundingAfter,inferredVariable:i.inferredVariable},fileContext:{fileExtension:n.fileExtension,isConfig:n.isConfig,isTest:n.isTest,isDoc:n.isDoc,isSensitiveName:n.isSensitiveName,isExampleOrSample:n.isExampleOrSample}};return{confidence:u,evidence:h,isSuppressed:!1}}function Ne(t,e,n,i){let s=[],r=0,o=Math.min(40,Math.round(t.baseRiskWeight/100*40));r+=o,s.push({factor:"CREDENTIAL_SEVERITY",weight:40,scoreContribution:o,explanation:`${t.provider} ${t.name} has high inherent privilege capability`});let a=Math.round(e/100*25);r+=a,s.push({factor:"CONFIDENCE_LEVEL",weight:25,scoreContribution:a,explanation:`Multi-signal verification confidence is ${e}%`});let d=5,p="Standard source code file";n.isConfig||n.isSensitiveName?(d=15,p="Located in sensitive deployment / environment configuration"):n.isTest?(d=0,p="Located in test / fixture codebase with reduced operational blast radius"):n.isDoc&&(d=0,p="Located in documentation context"),r+=d,s.push({factor:"STORAGE_ENVIRONMENT",weight:15,scoreContribution:d,explanation:p});let g=5,c="Found in local uncommitted working tree";i&&(i.isRemote?(g=20,c="Pushed to remote repository branch (external exposure risk)"):i.isPresentInHistory?(g=16,c=`Committed to Git history across ${i.branches.length||1} branch(es) (${i.exposureDurationDays} days exposure)`):i.isPresentInHead&&(g=12,c="Committed in current HEAD commit")),r+=g,s.push({factor:"EXPOSURE_REACH",weight:20,scoreContribution:g,explanation:c});let l=Math.max(0,Math.min(100,Math.round(r))),u="LOW";l>=76?u="CRITICAL":l>=51?u="HIGH":l>=26?u="MEDIUM":u="LOW";let h=Gt(l,i),v=`${u} Risk (${l}/100) \u2014 ${t.name}. ${h.summary}`;return{score:l,tier:u,factors:s,blastRadius:h,summary:v}}function Gt(t,e){let n=[],i=Math.round(t*.5),s=e?e.isPresentInHead:!0,r=e?e.isPresentInHistory:!1,o=e?.isPresentInHistory?1:0,a=e?.branches||["main"],d=a.length,p=e?.isRemote||!1,g=e?.exposureDurationDays||0;s&&(n.push("Active working tree contains exposed secret"),i+=15),r&&(n.push(`Git history contains commit records across ${d} branch(es)`),i+=20),p&&(n.push("Secret has been synchronized to remote tracking branches"),i+=25),g>7&&(n.push(`Exposure duration exceeds ${g} days without rotation`),i+=10),i=Math.max(0,Math.min(100,i));let c="CONTAINED";i>=75?c="SEVERE":i>=50?c="EXTENSIVE":i>=25?c="MODERATE":c="CONTAINED";let l=`Blast Radius: ${c} (${i}/100) \u2014 ${p?"Remote & history exposure":r?"Historical commit exposure":"Contained to local working tree"}`;return{level:c,score:i,workingTreeExposed:s,gitHistoryExposed:r,commitCount:o,branchCount:d,branches:a,remoteExposed:p,exposureDurationDays:g,summary:l,factors:n}}var Z=P(require("fs")),J=P(require("path"));var lt=P(require("crypto")),Vt="sld_fingerprint_salt_v1_d8e9f2a1b4c3e7f0";function pe(t){if(!t)return"";let e=t.length;if(e<=12)return"\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022";let n=Math.max(2,Math.floor(e*.2)),i=Math.min(4,Math.max(1,Math.floor(n/2))),s=Math.min(3,Math.max(1,n-i)),r=Math.max(6,Math.min(16,e-i-s)),o=t.substring(0,i),a=t.substring(e-s),d="\u2022".repeat(r);return`${o}${d}${a}`}function Oe(t){return lt.createHmac("sha256",Vt).update(t).digest("hex").substring(0,16)}function $e(t){return t.replace(/\\/g,"\\\\").replace(/"/g,'\\"').replace(/\$/g,"\\$").replace(/\n/g,"\\n").replace(/\r/g,"\\r")}function pt(t,e){switch(J.extname(t).toLowerCase()){case".py":return`os.environ.get("${e}")`;case".go":return`os.Getenv("${e}")`;case".rb":return`ENV['${e}']`;case".php":return`getenv('${e}')`;case".java":case".kt":return`System.getenv("${e}")`;case".rs":return`std::env::var("${e}").unwrap()`;case".sh":case".bash":case".zsh":return`"\${${e}}"`;case".yaml":case".yml":case".toml":case".env":return`\${${e}}`;case".js":case".jsx":case".ts":case".tsx":case".mjs":case".cjs":default:return`process.env.${e}`}}function Me(t,e,n,i,s){let r=t.suggestedEnvName(s),o=pt(n,r),a=pe(e),d=$e(e),p=[`1. Revoke / rotate credential immediately with provider: ${t.provider}`,`2. Migrate secret value to local .env file (${r})`,`3. Replace hardcoded literal in ${n} with ${o}`,"4. Verify .env is listed in .gitignore so it is never committed","5. If committed previously, purge from Git history using git-filter-repo or BFG","6. Rescan file and commit to verify exposure is eliminated"],g=`${r}="${d}"`,c=`${r}=your_${r.toLowerCase()}_here`,l=`# WARNING: Use BFG Repo Cleaner to purge secrets from history (safer than filter-repo --invert-paths):
#   java -jar bfg.jar --replace-text secrets.txt <repo-dir>
# Where secrets.txt lists the exact literal to redact (one per line).
# Then force-push: git push --force --all && git push --force --tags
# Alternatively with git-filter-repo (rewrites content, not paths):
#   git filter-repo --replace-text secrets.txt`,u=`--- a/${n}
+++ b/${n}
@@ -${i},1 +${i},1 @@
- ... "${a}" ...
+ ... ${o} ...`;return{steps:p,envVarName:r,replacementCode:o,envFileSnippet:g,envExampleSnippet:c,gitHistoryPurgeCommand:l,diffPreview:u}}function Ut(t,e,n){let i=t.split(/\r?\n/),s=new Map;for(let r of i){let o=r.trim();if(!o||o.startsWith("#"))continue;let a=o.indexOf("=");if(a!==-1){let d=o.substring(0,a).trim(),p=o.substring(a+1).trim();(p.startsWith('"')&&p.endsWith('"')||p.startsWith("'")&&p.endsWith("'"))&&(p=p.substring(1,p.length-1)),s.set(d,p)}}if(s.has(e)){let r=s.get(e);if(r===$e(n)||r===n)return{varName:e,isReused:!0};let o=2;for(;s.has(`${e}_${o}`);){if(s.get(`${e}_${o}`)===n)return{varName:`${e}_${o}`,isReused:!0};o++}return{varName:`${e}_${o}`,isReused:!1}}return{varName:e,isReused:!1}}function jt(t){let e=J.join(t,".gitignore");if(Z.existsSync(e)){let n=Z.readFileSync(e,"utf8");if(!n.split(/\r?\n/).some(r=>/^\s*\.env(?:\s|$)/.test(r))){let r=n.endsWith(`
`)||n.length===0?"":`
`;Z.appendFileSync(e,`${r}# Credentials
.env
.env.*.local
`,"utf8")}}else Z.writeFileSync(e,`# Credentials
.env
.env.*.local
`,"utf8");try{let{execFileSync:n}=require("child_process");try{n("git",["rev-parse","--is-inside-work-tree"],{cwd:t,stdio:"ignore"})}catch{return}try{throw n("git",["ls-files","--error-unmatch",".env"],{cwd:t,stdio:"ignore"}),new Error('.env is already tracked in Git index. Run "git rm --cached .env" to untrack it before storing secrets.')}catch(i){if(i.message&&i.message.includes("already tracked in Git index"))throw i}try{n("git",["check-ignore","-q",".env"],{cwd:t,stdio:"ignore"})}catch{throw new Error(".env is not ignored by Git according to git check-ignore.")}}catch(n){if(n.message&&(n.message.includes("already tracked")||n.message.includes("not ignored by Git")))throw n}}function ut(t,e,n=Z){let i=t.fullPath,s=null,r=null,o=null,a=null,d=!1,p=!1,g=!1,c=J.join(e,".env"),l=J.join(e,".gitignore");try{if(!n.existsSync(i))return{success:!1,message:`Target file not found: ${i}`,envPath:"",modifiedFile:i};if(s=n.readFileSync(i,"utf8"),!s.includes(t.rawSecret))return{success:!1,message:"Secret no longer found in target file (may have already been modified).",envPath:"",modifiedFile:i};let u="";if(n.existsSync(c))r=n.readFileSync(c,"utf8"),u=r;else{d=!0;try{n.writeFileSync(c,"",{mode:384,encoding:"utf8"})}catch{}}n.existsSync(l)?o=n.readFileSync(l,"utf8"):p=!0;let h=t.remediation?.envVarName||"API_KEY",{varName:v,isReused:b}=Ut(u,h,t.rawSecret),E=pt(i,v),m=$e(t.rawSecret),C=`${v}="${m}"
`;if(jt(e),!b){let x=u.endsWith(`
`)||u.length===0?"":`
`;n.appendFileSync(c,`${x}${C}`,"utf8");try{n.chmodSync(c,384)}catch{}}let _=J.join(e,".env.example"),L=`${v}=your_${v.toLowerCase()}_here
`,W=n.existsSync(_);if(W?a=n.readFileSync(_,"utf8"):g=!0,!W||!n.readFileSync(_,"utf8").includes(v)){let x=W?n.readFileSync(_,"utf8"):"",T=x.endsWith(`
`)||x.length===0?"":`
`;n.appendFileSync(_,`${T}${L}`,"utf8")}let k=s,S=`"${t.rawSecret}"`,y=`'${t.rawSecret}'`,I=`\`${t.rawSecret}\``;return k.includes(S)?k=k.replace(new RegExp(Se(S),"g"),E):k.includes(y)?k=k.replace(new RegExp(Se(y),"g"),E):k.includes(I)?k=k.replace(new RegExp(Se(I),"g"),E):k=k.replace(new RegExp(Se(t.rawSecret),"g"),E),n.writeFileSync(i,k,"utf8"),{success:!0,message:`Successfully migrated ${t.type} to .env (${v}) and replaced in ${t.file}.`,envPath:c,modifiedFile:i}}catch(u){let h=[],v=(m,C)=>{let _=`${m}.sld-tmp-${Date.now()}`;n.writeFileSync(_,C,"utf8"),n.renameSync(_,m)};if(s!==null)try{v(i,s),n.readFileSync(i,"utf8")!==s&&h.push(`source file restored with mismatched content (${i})`)}catch(m){h.push(`source file restore failed (${i}): ${m.message}`)}if(d&&n.existsSync(c))try{n.unlinkSync(c),n.existsSync(c)&&h.push(".env delete did not take effect")}catch(m){h.push(`.env delete failed: ${m.message}`)}else if(r!==null&&n.existsSync(c))try{v(c,r)}catch(m){h.push(`.env restore failed: ${m.message}`)}if(p&&n.existsSync(l))try{n.unlinkSync(l),n.existsSync(l)&&h.push(".gitignore delete did not take effect")}catch(m){h.push(`.gitignore delete failed: ${m.message}`)}else if(o!==null&&n.existsSync(l))try{v(l,o)}catch(m){h.push(`.gitignore restore failed: ${m.message}`)}let b=J.join(e,".env.example");if(g&&n.existsSync(b))try{n.unlinkSync(b),n.existsSync(b)&&h.push(".env.example delete did not take effect")}catch(m){h.push(`.env.example delete failed: ${m.message}`)}else if(a!==null&&n.existsSync(b))try{v(b,a)}catch(m){h.push(`.env.example restore failed: ${m.message}`)}let E=h.length===0?"Rollback completed successfully.":`ROLLBACK INCOMPLETE \u2014 manual inspection required: ${h.join("; ")}`;return{success:!1,message:`Remediation failed: ${u.message}. ${E}`,envPath:"",modifiedFile:t.fullPath}}}function Se(t){return t.replace(/[.*+?^${}()|[\]\\]/g,"\\$&")}function gt(t){return ft.createHash("sha256").update(t.replace(/\\/g,"/")).digest("hex").slice(0,8)}function Zt(t,e=4e3){if(t.length<e)return t;let n=!1,i=-1;for(let o=0;o<t.length;o++)if(t.charCodeAt(o)===10){if(o-i>e){n=!0;break}i=o}if(!n&&t.length-i<=e)return t;let s=t.split(/\r?\n/),r=[];for(let o of s)if(o.length<=e)r.push(o);else for(let a=0;a<o.length;a+=e-100)r.push(o.substring(a,a+e));return r.join(`
`)}function mt(t,e){return/(?:\/\/|#|\/\*|--)\s*(?:sld-ignore|secret-leak-ignore)/i.test(t)?!0:/^\s*(?:\/\/|#|\/\*|--)\s*(?:sld-ignore|secret-leak-ignore)(?:\s*\*\/)?\s*$/i.test(e)}function re(t,e,n={}){let i=typeof n=="string"?{workspaceRoot:n}:n,s=Zt(t),r=i.rules||Ve,o=i.workspaceRoot,a=Ue(e,o),d=s.split(/\r?\n/),p=[],g=null;function c(){if(!g){g=[0];for(let S=0;S<s.length;S++)s.charCodeAt(S)===10&&g.push(S+1)}return g}function l(S){let y=c(),I=0,x=y.length-1;for(;I<=x;){let T=I+x>>1;if(y[T]<=S){if(T===y.length-1||y[T+1]>S)return{line:T+1,column:S-y[T]+1};I=T+1}else x=T-1}return{line:1,column:S+1}}let u=null;function h(S){if(s.length<=1024*1024)return u||(u=s.split(/\r?\n/)),{lines:u,relativeTargetIdx:S-1};let y=c(),I=S-1,x=Math.max(0,I-30),T=Math.min(y.length-1,I+30),z=y[x],Q=T+1<y.length?y[T+1]:s.length;return{lines:s.substring(z,Q).split(/\r?\n/),relativeTargetIdx:I-x}}for(let S of r){S.pattern.lastIndex=0;let y;for(;(y=S.pattern.exec(s))!==null;){let I=y[1]!==void 0?y[1]:y[0],x=y[1]!==void 0?y[0].indexOf(y[1]):0,T=y.index+(x>=0?x:0),{line:z,column:Q}=l(T),se=d[z-1]||"",H=z>1?d[z-2]:"";if(!i?.disallowInlineIgnore&&mt(se,H))continue;let U=h(z),ee=Pe(U.lines,U.relativeTargetIdx),K=Fe(U.lines,U.relativeTargetIdx,e),$=Le(S,I,a,ee,e,K);if($.isSuppressed)continue;let j;if(S.minEntropy!==void 0&&(S.provider==="Generic"&&i.minEntropyThreshold!==void 0?j=i.minEntropyThreshold:j=S.minEntropy),j!==void 0&&$.evidence.shannonEntropy<j)continue;let te=e;if(o){let de=oe.relative(o,e);!de.startsWith("..")&&!oe.isAbsolute(de)&&(te=de)}let ce=Ne(S,$.confidence,a),fe=Me(S,I,te,z,ee.inferredVariable),he=gt(te),ve=Oe(I),Te=`sec_${ve}_${he}`,ne=pe(I),Rt={id:Te,fingerprint:ve,type:S.name,provider:S.provider,file:te,fullPath:e,line:z,column:Q,length:I.length,rawSecret:I,redactedSecret:ne,confidence:$.confidence,risk:ce.tier,riskAssessment:ce,evidence:$.evidence,remediation:fe,status:"ACTIVE",detectedAt:new Date().toISOString(),signals:$.evidence.items.map(de=>de.description),exampleFix:fe.replacementCode,entropy:$.evidence.shannonEntropy};p.push(Rt)}}let v=[],b=/["']([^"'\r\n]{2,80})["']\s*\+\s*["']([^"'\r\n]{8,120})["']/g,E;for(;(E=b.exec(s))!==null;)v.push({combined:E[1]+E[2],matchOffset:E.index,matchLength:E[0].length,description:"Resolved split string concatenation"});let m=/\[\s*["']([^"'\r\n]{2,80})["']\s*,\s*["']([^"'\r\n]{8,120})["'](?:\s*,\s*["']([^"'\r\n]{2,120})["'])*\s*\]\s*\.\s*join\s*\(\s*["']\s*["']\s*\)/g,C;for(;(C=m.exec(s))!==null;){let S=[C[1],C[2],C[3]].filter(Boolean);v.push({combined:S.join(""),matchOffset:C.index,matchLength:C[0].length,description:"Resolved split array join expression"})}let _=/`([^`\r\n]{2,80})\$\{\s*["']([^"'\r\n]{8,120})["']\s*\}([^`\r\n]*?)`/g,L;for(;(L=_.exec(s))!==null;)v.push({combined:L[1]+L[2]+(L[3]||""),matchOffset:L.index,matchLength:L[0].length,description:"Resolved template literal interpolation"});let W=/(?:Buffer\.from|atob|b64decode)\s*\(\s*(?:b)?["']([A-Za-z0-9+/=]{24,200})["']/g,k;for(;(k=W.exec(s))!==null;)try{let S=Buffer.from(k[1],"base64").toString("utf8");S.length>=10&&/^[\x20-\x7E\r\n]+$/.test(S)&&v.push({combined:S,matchOffset:k.index,matchLength:k[0].length,description:"Resolved base64-encoded credential payload"})}catch{}for(let S of v)for(let y of r){y.pattern.lastIndex=0;let I;for(;(I=y.pattern.exec(S.combined))!==null;){let x=I[1]||I[0],{line:T,column:z}=l(S.matchOffset),Q=d[T-1]||"",se=T>1?d[T-2]:"";if(mt(Q,se))continue;let H=h(T),U=Pe(H.lines,H.relativeTargetIdx),ee=Fe(H.lines,H.relativeTargetIdx,e),K=Le(y,x,a,U,e,ee);if(K.isSuppressed)continue;let $;if(y.minEntropy!==void 0&&(y.provider==="Generic"&&i.minEntropyThreshold!==void 0?$=i.minEntropyThreshold:$=y.minEntropy),$!==void 0&&K.evidence.shannonEntropy<$)continue;let j=e;if(o){let ne=oe.relative(o,e);!ne.startsWith("..")&&!oe.isAbsolute(ne)&&(j=ne)}let te=Ne(y,K.confidence,a),ce=Me(y,x,j,T,U.inferredVariable);K.evidence.items.unshift({signal:"ADVERSARIAL_DEOBFUSCATION_RESOLVED",description:S.description,confidenceImpact:10});let fe=gt(j),he=Oe(x),ve=`sec_${he}_${fe}`,Te=pe(x);p.push({id:ve,fingerprint:he,type:y.name,provider:y.provider,file:j,fullPath:e,line:T,column:z,length:S.matchLength,rawSecret:x,redactedSecret:Te,confidence:Math.min(100,K.confidence+5),risk:te.tier,riskAssessment:te,evidence:K.evidence,remediation:ce,status:"ACTIVE",detectedAt:new Date().toISOString(),signals:K.evidence.items.map(ne=>ne.description),exampleFix:ce.replacementCode,entropy:K.evidence.shannonEntropy})}}return Yt(p)}function Yt(t){let e=[];for(let n of t){let i=e.findIndex(s=>s.file===n.file&&s.line===n.line&&(s.rawSecret.includes(n.rawSecret)||n.rawSecret.includes(s.rawSecret)));if(i===-1)e.push(n);else{let s=e[i];(s.provider==="Generic Credential"&&n.provider!=="Generic Credential"||n.confidence>s.confidence)&&(e[i]=n)}}return e}var Ae=class{diagnosticCollection;currentFindings=new Map;ignoredFindings=new Set;onFindingsChangedEmitter=new R.EventEmitter;onFindingsChanged=this.onFindingsChangedEmitter.event;minEntropy;constructor(){this.diagnosticCollection=R.languages.createDiagnosticCollection("secret-leak-detector")}setMinEntropy(e){this.minEntropy=e}getDiagnosticCollection(){return this.diagnosticCollection}getAllFindings(){let e=[];for(let n of this.currentFindings.values())e.push(...n);return e}clear(){this.diagnosticCollection.clear(),this.currentFindings.clear(),this.onFindingsChangedEmitter.fire([])}ignoreFinding(e){this.ignoredFindings.add(e);for(let[n,i]of this.currentFindings.entries()){let s=i.filter(r=>r.id!==e);if(s.length!==i.length){this.currentFindings.set(n,s);let r=R.Uri.file(n),o=this.diagnosticCollection.get(r);if(o){let a=o.filter(d=>(typeof d.code=="object"?d.code?.value:d.code)!==e);this.diagnosticCollection.set(r,a)}}}this.onFindingsChangedEmitter.fire(this.getAllFindings())}setIgnoredFindings(e){this.ignoredFindings=new Set(e)}getIgnoredFindings(){return Array.from(this.ignoredFindings)}scanDocument(e){if(e.uri.scheme!=="file")return[];let n=e.getText();if(n.length>5*1024*1024)return[];let i=R.workspace.getWorkspaceFolder(e.uri),r={workspaceRoot:i?i.uri.fsPath:void 0,minEntropyThreshold:this.minEntropy},a=re(n,e.uri.fsPath,r).filter(p=>!this.ignoredFindings.has(p.id));this.currentFindings.set(e.uri.fsPath,a);let d=[];for(let p of a){let g=Math.max(0,p.line-1),c=Math.max(0,p.column-1),l=new R.Position(g,c),u=e.offsetAt(l),h=e.positionAt(u+p.length),v=new R.Range(l,h),b=R.DiagnosticSeverity.Warning;p.risk==="CRITICAL"||p.risk==="HIGH"?b=R.DiagnosticSeverity.Error:p.risk==="LOW"&&(b=R.DiagnosticSeverity.Information);let E=typeof p.remediation=="string"?p.remediation:p.remediation?.steps?.[0]||"Migrate to .env",m=new R.Diagnostic(v,`[Secret Leak Detector] ${p.type} detected! Confidence: ${p.confidence}%. ${E}`,b);m.code={value:p.id,target:R.Uri.parse("https://github.com/MokuLakshithReddy/Secret_Leak_Detector")},m.source="Secret Leak Detector",d.push(m)}return this.diagnosticCollection.set(e.uri,d),this.onFindingsChangedEmitter.fire(this.getAllFindings()),a}toDiagnostic(e){let n=Math.max(0,e.line-1),i=Math.max(0,e.column-1),s=new R.Position(n,i),r,o=e.rawSecret||(e.evidence?.surroundingCode?.targetLine?e.redactedSecret:"");if(o&&o.includes(`
`)){let c=o.split(/\r?\n/),l=n+c.length-1,u=c.length>1?c[c.length-1].length:i+c[0].length;r=new R.Position(l,u)}else r=new R.Position(n,i+e.length);let a=new R.Range(s,r),d=R.DiagnosticSeverity.Warning;e.risk==="CRITICAL"||e.risk==="HIGH"?d=R.DiagnosticSeverity.Error:e.risk==="LOW"&&(d=R.DiagnosticSeverity.Information);let p=typeof e.remediation=="string"?e.remediation:e.remediation?.steps?.[0]||"Migrate to .env",g=new R.Diagnostic(a,`[Secret Leak Detector] ${e.type} detected! Confidence: ${e.confidence}%. ${p}`,d);return g.code={value:e.id,target:R.Uri.parse("https://github.com/MokuLakshithReddy/Secret_Leak_Detector")},g.source="Secret Leak Detector",g}setBatchFindings(e){this.diagnosticCollection.clear(),this.currentFindings.clear();for(let[n,i]of e.entries()){let s=i.filter(r=>!this.ignoredFindings.has(r.id));if(this.currentFindings.set(n,s),s.length>0){let r=R.Uri.file(n),o=s.map(a=>this.toDiagnostic(a));this.diagnosticCollection.set(r,o)}}this.onFindingsChangedEmitter.fire(this.getAllFindings())}renameDocument(e,n){let i=this.currentFindings.get(e.fsPath);if(this.removeDocument(e),i&&i.length>0){let s=i.map(o=>({...o,fullPath:n.fsPath,file:n.fsPath}));this.currentFindings.set(n.fsPath,s);let r=s.map(o=>this.toDiagnostic(o));this.diagnosticCollection.set(n,r),this.onFindingsChangedEmitter.fire(this.getAllFindings())}}removeDocument(e){this.diagnosticCollection.delete(e),this.currentFindings.delete(e.fsPath),this.onFindingsChangedEmitter.fire(this.getAllFindings())}dispose(){this.diagnosticCollection.dispose(),this.onFindingsChangedEmitter.dispose()}};var O=P(require("vscode"));var ae=class{static providedCodeActionKinds=[O.CodeActionKind.QuickFix];diagnosticProvider;constructor(e){this.diagnosticProvider=e}provideCodeActions(e,n,i){let s=[],r=i.diagnostics.filter(a=>a.source==="Secret Leak Detector");if(r.length===0)return s;let o=this.diagnosticProvider.getAllFindings();for(let a of r){let d=typeof a.code=="object"?a.code?.value:a.code,p=o.find(u=>u.id===d);if(!p||e.getText(a.range)!==p.rawSecret)continue;let c=this.createMoveToEnvAction(e,a.range,p);s.push(c);let l=new O.CodeAction("Ignore this finding (False Positive)",O.CodeActionKind.QuickFix);l.command={command:"secret-leak-detector.ignoreFinding",title:"Ignore Finding",arguments:[p.id]},s.push(l)}return s}createMoveToEnvAction(e,n,i){let s=new O.CodeAction(`\u{1F6E1}\uFE0F Move ${i.type} to .env and replace with environment variable`,O.CodeActionKind.QuickFix);return s.isPreferred=!0,s.command={command:"secret-leak-detector.remediateFinding",title:"Move to .env",arguments:[e.uri,n,i]},s}static async executeRemediation(e,n,i){let s=O.workspace.getWorkspaceFolder(e);if(!s){O.window.showErrorMessage("No workspace folder found to save .env file.");return}let r=s.uri.fsPath;if((await O.workspace.openTextDocument(e)).getText(n)!==i.rawSecret){O.window.showErrorMessage("The secret at the target location has changed or was already removed.");return}let a=ut(i,r);if(!a.success){O.window.showErrorMessage(`Remediation aborted: ${a.message}`);return}O.window.showInformationMessage(`\u{1F6E1}\uFE0F ${a.message}`)}};var A=P(require("vscode")),Ee=class{_onDidChangeTreeData=new A.EventEmitter;onDidChangeTreeData=this._onDidChangeTreeData.event;findings=[];updateFindings(e){this.findings=e,this._onDidChangeTreeData.fire()}getTreeItem(e){return e}getChildren(e){if(!e){if(this.findings.length===0){let s=new V("No Leaks Detected (Safe)",A.TreeItemCollapsibleState.None);return s.iconPath=new A.ThemeIcon("shield-check",new A.ThemeColor("testing.iconPassed")),s.description="Workspace is clean",Promise.resolve([s])}let n=["CRITICAL","HIGH","MEDIUM","LOW"],i=[];for(let s of n){let r=this.findings.filter(o=>o.risk===s).length;if(r>0){let o=new V(`${s} Risk (${r})`,A.TreeItemCollapsibleState.Expanded,s);s==="CRITICAL"?o.iconPath=new A.ThemeIcon("error",new A.ThemeColor("errorForeground")):s==="HIGH"?o.iconPath=new A.ThemeIcon("warning",new A.ThemeColor("editorWarning.foreground")):s==="MEDIUM"?o.iconPath=new A.ThemeIcon("info",new A.ThemeColor("editorInfo.foreground")):o.iconPath=new A.ThemeIcon("pass",new A.ThemeColor("testing.iconPassed")),i.push(o)}}return Promise.resolve(i)}if(e.contextValue){let n=e.contextValue,i=this.findings.filter(o=>o.risk===n),s=A.workspace.getConfiguration("secretLeakDetector").get("redactSecrets",!0),r=i.map(o=>{let a=new V(`${o.type}`,A.TreeItemCollapsibleState.None),d=s?o.redactedSecret:o.rawSecret;return a.description=`${o.file}:${o.line}`,a.tooltip=new A.MarkdownString(`**${o.type}** (${o.provider})

- **Risk:** ${o.risk}
- **Confidence:** ${o.confidence}%
- **Entropy:** ${o.entropy} bits/char
- **Secret:** \`${d}\`

*Suggested Fix: ${o.remediation?.replacementCode||o.remediation?.envVarName||"Migrate to .env"}*`),a.iconPath=new A.ThemeIcon("key"),a.command={command:"vscode.open",title:"Jump to Secret",arguments:[A.Uri.file(o.fullPath),{selection:new A.Range(o.line-1,o.column-1,o.line-1,o.column-1+o.length)}]},a});return Promise.resolve(r)}return Promise.resolve([])}},xe=class{_onDidChangeTreeData=new A.EventEmitter;onDidChangeTreeData=this._onDidChangeTreeData.event;findingsCount=0;isGit=!0;update(e,n){this.findingsCount=e,this.isGit=n,this._onDidChangeTreeData.fire()}getTreeItem(e){return e}getChildren(){let e=[],n=new V(this.findingsCount===0?"Status: Protected":`Status: ${this.findingsCount} Leaks Active`,A.TreeItemCollapsibleState.None);n.iconPath=new A.ThemeIcon(this.findingsCount===0?"check":"alert",this.findingsCount===0?new A.ThemeColor("testing.iconPassed"):new A.ThemeColor("errorForeground")),e.push(n);let i=new V("Run Full Workspace Scan",A.TreeItemCollapsibleState.None);i.iconPath=new A.ThemeIcon("search"),i.command={command:"secret-leak-detector.scanWorkspace",title:"Scan Workspace"},e.push(i);let s=new V("Check Git Staged Changes",A.TreeItemCollapsibleState.None);s.iconPath=new A.ThemeIcon("git-commit"),s.command={command:"secret-leak-detector.scanStaged",title:"Scan Staged Changes"},e.push(s);let r=new V("Open Interactive Dashboard",A.TreeItemCollapsibleState.None);r.iconPath=new A.ThemeIcon("dashboard"),r.command={command:"secret-leak-detector.openDashboard",title:"Open Dashboard"},e.push(r);let o=new V("Install Pre-Commit Hook",A.TreeItemCollapsibleState.None);return o.iconPath=new A.ThemeIcon("terminal"),o.command={command:"secret-leak-detector.installGitHook",title:"Install Hook"},e.push(o),Promise.resolve(e)}},V=class extends A.TreeItem{constructor(e,n,i){super(e,n),this.contextValue=i}};var D=P(require("vscode")),ht=P(require("crypto")),We=P(require("fs")),ue=P(require("path"));function Be(t){let e=typeof t.remediation=="string"?t.remediation:t.remediation?.steps?.join("; ")||"Rotate and move to .env",n=t.exampleFix||t.remediation?.replacementCode||"";return{id:t.id,type:t.type,provider:t.provider,file:t.file,fullPath:t.fullPath,line:t.line,column:t.column,redactedSecret:t.redactedSecret,confidence:t.confidence,entropy:t.entropy??0,risk:t.risk,remediationText:e,exampleFix:n}}var ie=class t{static currentPanel;static viewType="secretLeakDetectorDashboard";_panel;_extensionUri;_disposables=[];_findings=[];static createOrShow(e,n){let i=D.window.activeTextEditor?D.window.activeTextEditor.viewColumn:void 0;if(t.currentPanel){t.currentPanel._panel.reveal(i),t.currentPanel.updateFindings(n);return}let s=D.window.createWebviewPanel(t.viewType,"\u{1F510} Secret Leak Detector Dashboard",i||D.ViewColumn.One,{enableScripts:!0,retainContextWhenHidden:!0,localResourceRoots:[e]});t.currentPanel=new t(s,e,n)}constructor(e,n,i){this._panel=e,this._extensionUri=n,this._findings=i,this._update(),this._panel.onDidDispose(()=>this.dispose(),null,this._disposables),this._panel.webview.onDidReceiveMessage(async s=>{switch(s.command){case"scanWorkspace":D.commands.executeCommand("secret-leak-detector.scanWorkspace");return;case"scanStaged":D.commands.executeCommand("secret-leak-detector.scanStaged");return;case"installHook":D.commands.executeCommand("secret-leak-detector.installGitHook");return;case"openFile":if(typeof s.file=="string"&&s.file.trim().length>0&&typeof s.line=="number"&&s.line>=1){let r=this._findings.find(a=>a.file===s.file||a.fullPath===s.file);if(!r)return;let o=r.fullPath||r.file;if(!ue.isAbsolute(o)){let a=!1;for(let d of D.workspace.workspaceFolders||[]){let p=ue.resolve(d.uri.fsPath,o);if(We.existsSync(p)){o=p,a=!0;break}}if(!a){let d=D.workspace.workspaceFolders?.[0]?.uri.fsPath||process.cwd();o=ue.resolve(d,o)}}if(We.existsSync(o))try{let a=await D.workspace.openTextDocument(D.Uri.file(o));await D.window.showTextDocument(a,{selection:new D.Range(s.line-1,0,s.line-1,0)})}catch{}}return}},null,this._disposables)}updateFindings(e){this._findings=e;let n=this._findings.map(Be);this._panel.webview.postMessage({command:"updateData",findings:n})}dispose(){for(t.currentPanel=void 0,this._panel.dispose();this._disposables.length;){let e=this._disposables.pop();e&&e.dispose()}}_update(){this._panel.webview.html=this._getHtmlForWebview()}_getHtmlForWebview(){let e=ht.randomBytes(16).toString("base64"),n=this._findings.map(Be),i=JSON.stringify(n).replace(/</g,"\\u003c");return`<!DOCTYPE html>
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
</html>`}};var It=require("child_process"),wt=require("util"),w=P(require("fs")),F=P(require("path"));var Y=require("child_process"),St=require("util"),Re=P(require("path"));var Ce=P(require("fs")),vt=P(require("path")),Ie=new Set([".png",".jpg",".jpeg",".gif",".bmp",".ico",".webp",".tiff",".tif",".pdf",".zip",".tar",".gz",".bz2",".7z",".rar",".exe",".dll",".so",".dylib",".bin",".iso",".dmg",".woff",".woff2",".ttf",".eot",".otf",".mp3",".mp4",".avi",".mov",".wmv",".flv",".mkv",".pyc",".pyo",".class",".jar",".war",".sqlite",".db",".dat"]),bt=["**/node_modules/**","node_modules/**","**/.git/**",".git/**","**/dist/**","dist/**","**/build/**","build/**","**/*.min.js","*.min.js","**/*.lock","*.lock","**/package-lock.json","package-lock.json","**/pnpm-lock.yaml","pnpm-lock.yaml"];function yt(t){if(!!(process.env.CI||process.env.GITHUB_ACTIONS||process.env.GITLAB_CI))try{let{execFileSync:i}=require("child_process"),s=process.env.GITHUB_BASE_REF||process.env.CI_MERGE_REQUEST_TARGET_BRANCH_NAME,r=s?[`origin/${s}`,`refs/remotes/origin/${s}`,s]:["origin/main","origin/master"];for(let o of r)try{let a=i("git",["show",`${o}:.sldignore`],{cwd:t,encoding:"utf8",stdio:["ignore","pipe","ignore"]});if(a)return a.split(/\r?\n/).map(d=>d.trim()).filter(d=>d.length>0&&!d.startsWith("#"))}catch{}return[]}catch{return[]}let n=vt.join(t,".sldignore");if(Ce.existsSync(n))try{return Ce.readFileSync(n,"utf8").split(/\r?\n/).map(s=>s.trim()).filter(s=>s.length>0&&!s.startsWith("#"))}catch{}return[]}function qt(t){let e=t.trim().replace(/\\/g,"/"),n=!1;e.endsWith("/")&&(n=!0,e=e.slice(0,-1)),e.startsWith("/")&&(e=e.slice(1));let i="",s=0;for(;s<e.length;)e.slice(s,s+4)==="/**/"?(i+="(?:/|/.*/)",s+=4):e.slice(s,s+3)==="/**"?(i+="(/.*)?",s+=3):e.slice(s,s+3)==="**/"?(i+="(?:^|.*/)",s+=3):e.slice(s,s+2)==="**"?(i+=".*",s+=2):e[s]==="*"?(i+="[^/]*",s+=1):e[s]==="?"?(i+="[^/]",s+=1):[".","+","^","$","(",")","[","]","{","}","|"].includes(e[s])?(i+="\\"+e[s],s+=1):(i+=e[s],s+=1);return n?new RegExp("(?:^|/)"+i+"(/.*)?$"):e.includes("/")?new RegExp("^"+i+"$"):new RegExp("(?:^|/)"+i+"$")}function kt(t,e){let n=t.replace(/\\/g,"/").replace(/^\/+/,""),i=e.trim().replace(/\\/g,"/");if(!i||i.startsWith("#"))return!1;if(n===i)return!0;let s=i.endsWith("/")?i.slice(0,-1):i;if(n===s||n.startsWith(s+"/"))return!0;try{return qt(i).test(n)}catch{return!1}}var Zn=(0,St.promisify)(Y.execFile),we=["-c","core.quotepath=false","-c","diff.noprefix=false","-c","diff.mnemonicPrefix=false","-c","color.diff=never"],Jt=5*1024*1024;function Xt(t){try{let e=(0,Y.execFileSync)("git",["rev-parse","--show-toplevel"],{cwd:t,encoding:"utf8"}).trim();if(e)return Re.resolve(e)}catch{}return t}function Qt(t){let e=[],n=[],i=0;for(let r=0;r<t.length;r++)t[r]===0&&(n.push(t.toString("utf8",i,r)),i=r+1);let s=0;for(;s<n.length;){let r=n[s++];if(!r)break;let o=r[0];if(o==="R"||o==="C"){let a=n[s++],d=n[s++];d&&e.push({status:o,path:d.replace(/\\/g,"/"),oldPath:a?a.replace(/\\/g,"/"):void 0})}else{let a=n[s++];a&&e.push({status:o,path:a.replace(/\\/g,"/")})}}return e}function en(t){if(t.length===0)return"";if(t.length>=2&&t[0]===255&&t[1]===254)return t.subarray(2).toString("utf16le");if(t.length>=2&&t[0]===254&&t[1]===255){let i=Buffer.from(t.subarray(2));return i.swap16(),i.toString("utf16le")}if(t.length>=4){let i=0,s=0,r=Math.min(t.length,512);for(let o=0;o<r;o++)t[o]===0&&(o%2===1?i++:s++);if(i>r*.35&&s<r*.05)return t.toString("utf16le")}let e=Math.min(t.length,1024),n=0;for(let i=0;i<e;i++)t[i]===0&&n++;return n>0?null:t.toString("utf8")}function tn(t,e){let n=new Map;if(e.length===0)return n;let i=e.map(r=>`:${r}
`).join(""),s=(0,Y.spawnSync)("git",[...we,"cat-file","--batch-check"],{cwd:t,input:i,encoding:"utf8",maxBuffer:64*1024*1024});if(s.stdout){let r=s.stdout.split(/\r?\n/);for(let o=0;o<e.length;o++){let a=r[o];if(!a)continue;let d=a.split(" ");d.length>=3&&d[1]==="blob"&&n.set(e[o],parseInt(d[2],10)||0)}}return n}function nn(t,e){let n=new Map;if(e.length===0)return n;let i=e.map(d=>`:${d}
`).join(""),r=(0,Y.spawnSync)("git",[...we,"cat-file","--batch"],{cwd:t,input:i,maxBuffer:64*1024*1024}).stdout;if(!r||r.length===0)return n;let o=0,a=0;for(;o<r.length&&a<e.length;){let d=r.indexOf(10,o);if(d===-1)break;let p=r.toString("utf8",o,d).trim();o=d+1;let g=p.split(" ");if(g.length>=3&&g[1]==="blob"){let c=parseInt(g[2],10),l=r.subarray(o,o+c);n.set(e[a++],l),o+=c,o<r.length&&r[o]===10&&o++}else a++}return n}function sn(t){let e=new Map,n=t.split(/^diff --git /m);for(let i of n){if(!i.trim())continue;let o=i.split(/\r?\n/)[0].match(/a\/(.+)\s+b\/(.+)/);if(!o)continue;let a=o[2].trim().replace(/\\/g,"/");if(a==="/dev/null")continue;let d=new Set,p=/^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/gm,g;for(;(g=p.exec(i))!==null;){let c=parseInt(g[1],10),l=g[2]!==void 0?parseInt(g[2],10):1;for(let u=0;u<l;u++)d.add(c+u)}d.size>0?e.set(a,d):(i.includes("rename to ")||i.includes("new file mode "))&&e.set(a,new Set([-1]))}return e}function ze(t,e){let n=Xt(t),i;try{i=(0,Y.execFileSync)("git",[...we,"diff","--cached","-z","--name-status","--no-color","--no-ext-diff","--src-prefix=a/","--dst-prefix=b/"],{cwd:n,maxBuffer:64*1024*1024})}catch(m){return{status:"ERROR",findings:[],error:`git diff --cached failed: ${m.message||String(m)}`}}let r=Qt(i).filter(m=>m.status!=="D");if(r.length===0)return{status:"CLEAN",findings:[],skippedFiles:[],filesScanned:0};let o=[...bt,...yt(n)],a=[],d=[];for(let m of r){let C=m.path,_=Re.extname(C).toLowerCase();if(!o.some(L=>kt(C,L))){if(Ie.has(_)){a.push({path:C,reason:"Binary file extension skipped"});continue}d.push(C)}}if(d.length===0)return{status:"CLEAN",findings:[],skippedFiles:a,filesScanned:0};let p=tn(n,d),g=[];for(let m of d){let C=p.get(m);if(C===void 0){a.push({path:m,reason:"Could not inspect blob size"});continue}if(C>Jt){a.push({path:m,reason:`File size (${(C/(1024*1024)).toFixed(1)}MB) exceeds 5MB limit`});continue}g.push(m)}if(g.length===0)return{status:"CLEAN",findings:[],skippedFiles:a,filesScanned:0};let c=nn(n,g),l=new Map;for(let m of g){let C=c.get(m);if(!C){a.push({path:m,reason:"Could not read staged blob"});continue}let _=en(C);if(_===null){a.push({path:m,reason:"Binary content detected"});continue}l.set(m,_)}let u=Array.from(l.keys());if(u.length===0)return{status:"CLEAN",findings:[],skippedFiles:a,filesScanned:0};let h="";try{h=(0,Y.execFileSync)("git",[...we,"diff","--cached","-U0","--no-color","--no-ext-diff","--src-prefix=a/","--dst-prefix=b/","--",...u],{cwd:n,encoding:"utf8",maxBuffer:64*1024*1024})}catch{h=""}let v=sn(h),b=[],E=0;for(let m of u){let C=l.get(m);if(!C)continue;let _=v.get(m)||new Set([-1]),L={workspaceRoot:n,disallowInlineIgnore:e?.disallowInlineIgnore},W=re(C,m,L);E++;for(let k of W)(_.has(-1)||_.has(k.line))&&b.push(k)}return{status:b.length>0?"FINDINGS":"CLEAN",findings:b,skippedFiles:a,filesScanned:E}}async function At(t,e){return new Promise(n=>{try{let i=ze(t,e);n(i)}catch(i){n({status:"ERROR",findings:[],error:i.message||String(i)})}})}var Ke=["LOW","MEDIUM","HIGH","CRITICAL"],He={LOW:1,MEDIUM:2,HIGH:3,CRITICAL:4},M="HIGH";function on(t){return typeof t=="string"&&Ke.includes(t.toUpperCase())}function _e(t,e=M){return on(t)?t.toUpperCase():e}function Et(t,e=M){return(He[t]||0)>=(He[e]||He.CRITICAL)}var ge="# [SLD_HOOK_MANAGED]";function xt(t=M,e,n,i=!0){let s=Ke.includes(t)?t:M,r=e?e.replace(/\\/g,"/"):"",o=r?r.replace(/'/g,"'\\''"):"",a=n?n.replace(/\\/g,"/"):"",d=a?a.replace(/'/g,"'\\''"):"",p=d?`# Resolved Node.js executable (prefer system node on PATH, fallback to pinned runtime)
if command -v node >/dev/null 2>&1; then
  NODE_CMD='node'
elif [ -x '${d}' ]; then
  NODE_CMD='${d}'
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
fi`,g=r?`# Scanner pinned to bundled CLI path
PINNED_CLI='${o}'
if [ -n "$PINNED_CLI" ] && [ -f "$PINNED_CLI" ]; then
  if [ -z "$NODE_CMD" ]; then
    echo ""
    echo "\u274C COMMIT BLOCKED: Node.js runtime not found on PATH (exit 127)."
    echo "   The pre-commit hook requires Node.js (>=18) to execute the scanner."
    echo "   Ensure 'node' is in your PATH or configure your Git client environment."
    exit 127
  fi
  export ELECTRON_RUN_AS_NODE=1
  "$NODE_CMD" "$PINNED_CLI" scan --staged --fail-on "$SLD_FAIL_ON"
  SCAN_STATUS=$?
elif command -v secret-leak-detector >/dev/null 2>&1; then
  secret-leak-detector scan --staged --fail-on "$SLD_FAIL_ON"
  SCAN_STATUS=$?
else
  echo ""
  echo "\u274C COMMIT BLOCKED (fail-closed): Secret Leak Detector scanner is unavailable."
  echo "   Pinned CLI ($PINNED_CLI) not found and no global CLI available."
  echo "   Staged changes could not be verified secret-free, so the commit was refused."
  echo ""
  echo "   Recovery guidance (if Secret Leak Detector was uninstalled):"
  echo "     rm .git/hooks/pre-commit"
  echo "     (or restore your original hook from .git/hooks/pre-commit.sld-backup.*)"
  echo "     git config --unset-all core.hooksPath"
  echo "   Or reinstall Secret Leak Detector in VS Code."
  exit 2
fi`:`# Scanner determined from environment or global binary (never ./dist/cli.js relative to repo)
if [ -n "$SLD_CLI_PATH" ] && [ -f "$SLD_CLI_PATH" ]; then
  if [ -z "$NODE_CMD" ]; then
    echo ""
    echo "\u274C COMMIT BLOCKED: Node.js runtime not found on PATH (exit 127)."
    echo "   The pre-commit hook requires Node.js (>=18) to execute the scanner."
    exit 127
  fi
  export ELECTRON_RUN_AS_NODE=1
  "$NODE_CMD" "$SLD_CLI_PATH" scan --staged --fail-on "$SLD_FAIL_ON"
  SCAN_STATUS=$?
elif command -v secret-leak-detector >/dev/null 2>&1; then
  secret-leak-detector scan --staged --fail-on "$SLD_FAIL_ON"
  SCAN_STATUS=$?
else
  echo ""
  echo "\u274C COMMIT BLOCKED (fail-closed): Secret Leak Detector scanner is unavailable."
  echo "   Staged changes could not be verified secret-free, so the commit was refused."
  echo "   Install Node.js (>=18) or the 'secret-leak-detector' CLI, then retry."
  exit 2
fi`;return`#!/bin/sh
${ge}
# Secret Leak Detector Pre-Commit Hook
# Intercepts git commit and blocks unredacted credentials before they leave the machine.
#
# Severity policy (single source of truth: src/core/policy.ts):
#   Blocks findings at ${s} and above (LOW < MEDIUM < HIGH < CRITICAL).
#   Lower tiers are reported but do not block.
#
# Fail-closed: if the scanner cannot be executed, the commit is BLOCKED.
SLD_FAIL_ON="${s}"
SLD_BLOCK_COMMITS="${i?"1":"0"}"

echo "\u{1F510} [Secret Leak Detector] Inspecting staged changes for credentials..."

${p}

${g}

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
`}var Ct=(0,wt.promisify)(It.execFile);var X=class{workspaceRoot;cliPath;onWarn;constructor(e,n,i){if(this.workspaceRoot=e,typeof n=="function"?this.onWarn=n:n&&w.existsSync(n)?(this.cliPath=n,this.onWarn=i):this.onWarn=i,!this.cliPath)if(process.env.SLD_CLI_PATH&&w.existsSync(process.env.SLD_CLI_PATH))this.cliPath=process.env.SLD_CLI_PATH;else{let s=[F.resolve(__dirname,"cli.js"),F.resolve(__dirname,"../cli/index.js"),F.resolve(__dirname,"../../dist/cli.js")];this.cliPath=s.find(r=>w.existsSync(r))}}async isGitRepo(){try{return await Ct("git",["rev-parse","--is-inside-work-tree"],{cwd:this.workspaceRoot}),!0}catch{return!1}}async scanStagedChanges(){return At(this.workspaceRoot)}scanStagedChangesSync(){return ze(this.workspaceRoot)}formatTerminalBlockedMessage(e){let i=e.filter(d=>d.risk==="CRITICAL")[0]||e[0],s=typeof i.remediation=="string"?i.remediation:i.remediation?.steps?.join(`
`)||"Rotate and move to .env",r=i.evidence?.items?.map(d=>`  - [${d.confidenceImpact>=0?"+":""}${d.confidenceImpact}] ${d.description}`).join(`
`)||i.signals?.map(d=>`  - ${d}`).join(`
`)||"  - Known pattern match",o=i.riskAssessment?.blastRadius?`${i.riskAssessment.blastRadius.level} (${i.riskAssessment.blastRadius.summary})`:"Local Working Tree";return`
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
\u2022 Blast Radius: ${o}

Evidence & Signals Detected:
${r}

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
`}async resolveHooksDir(){try{let{stdout:e}=await Ct("git",["rev-parse","--git-path","hooks"],{cwd:this.workspaceRoot}),n=e.trim();return F.isAbsolute(n)?n:F.resolve(this.workspaceRoot,n)}catch{return F.join(this.workspaceRoot,".git","hooks")}}async installPreCommitHook(e,n,i=!0,s=M){if(!await this.isGitRepo())return{success:!1,message:"Workspace is not a Git repository."};let r=await this.resolveHooksDir();if(!w.existsSync(r))try{w.mkdirSync(r,{recursive:!0})}catch(u){return{success:!1,message:`Could not create hooks directory (${r}): ${u}`}}let o=F.join(r,"pre-commit"),a=Date.now(),d=F.join(r,`pre-commit.sld-backup.${a}`),p=F.join(r,"pre-commit.sld-backup.latest"),g=ge;if(w.existsSync(o))try{let u=w.readFileSync(o,"utf8");u.includes(g)||(w.writeFileSync(d,u,{mode:493}),w.writeFileSync(p,d,"utf8"))}catch(u){return{success:!1,message:`Could not backup existing hook: ${u}`}}let c=e||this.cliPath;if(!c||!w.existsSync(c))return{success:!1,message:`Cannot install pre-commit hook: bundled CLI binary not found at '${c||"undefined"}'. Installation aborted.`};if(/[\/\\](?:_npx|Temp|tmp)[\/\\]/i.test(c)){let u=`\u26A0\uFE0F Warning: Pre-commit hook is pinning a temporary/npx CLI path: '${c}'. This path may be deleted automatically by your system. Consider installing secret-leak-detector globally or locally.`;this.onWarn?this.onWarn(u):console.warn(u)}let l=xt(s,c,n,i);try{return w.writeFileSync(o,l,{mode:493}),{success:!0,message:`Pre-commit hook successfully installed to ${o}`}}catch(u){return{success:!1,message:`Failed to write hook file: ${u}`}}}async ensureHookIsPinned(e,n,i=!0,s=M){if(!e||!w.existsSync(e)||!await this.isGitRepo())return!1;let r=await this.resolveHooksDir(),o=F.join(r,"pre-commit");if(!w.existsSync(o))return!1;try{let a=w.readFileSync(o,"utf8");if(!a.includes(ge))return!1;let d=e.replace(/\\/g,"/"),p=`SLD_FAIL_ON="${s}"`,g=`SLD_BLOCK_COMMITS="${i?"1":"0"}"`,c=a.includes("ELECTRON_RUN_AS_NODE=1");if(!a.includes(d)||!a.includes(p)||!a.includes(g)||!c)return(await this.installPreCommitHook(e,n,i,s)).success}catch{return!1}return!0}async uninstallPreCommitHook(){let e=await this.resolveHooksDir(),n=F.join(e,"pre-commit"),i=F.join(e,"pre-commit.sld-backup.latest");if(!w.existsSync(n))return{success:!0,message:"No pre-commit hook found to uninstall."};try{if(!w.readFileSync(n,"utf8").includes(ge))return{success:!1,message:"Existing pre-commit hook is not managed by Secret Leak Detector; refusing to delete user hook."};if(w.existsSync(i)){let r=w.readFileSync(i,"utf8").trim(),o=F.resolve(r),a=F.resolve(e),d=F.basename(o);if(F.dirname(o)===a&&/^pre-commit\.sld-backup\.\d+$/.test(d)&&w.existsSync(o))return w.copyFileSync(o,n),w.unlinkSync(o),w.unlinkSync(i),{success:!0,message:"Uninstalled SLD hook and restored original pre-commit hook."};try{w.unlinkSync(i)}catch{}}return w.unlinkSync(n),{success:!0,message:"Removed Secret Leak Detector pre-commit hook."}}catch(s){return{success:!1,message:`Failed to uninstall hook: ${s.message}`}}}};var N,me=new Map;function rn(t){N=f.window.createOutputChannel("Secret Leak Detector"),t.subscriptions.push(N),N.appendLine("\u{1F510} [Secret Leak Detector] Extension activated.");let e=new Ae;t.subscriptions.push(e),t.subscriptions.push(f.languages.registerCodeActionsProvider({scheme:"file"},new ae(e),{providedCodeActionKinds:ae.providedCodeActionKinds}));let n=new Ee,i=new xe;t.subscriptions.push(f.window.registerTreeDataProvider("secret-leak-detector.findingsView",n)),t.subscriptions.push(f.window.registerTreeDataProvider("secret-leak-detector.overviewView",i));let s=f.workspace.workspaceFolders?.[0],r=s?s.uri.fsPath:process.cwd(),o=new X(r,c=>N.appendLine(c));e.onFindingsChanged(c=>{n.updateFindings(c),i.update(c.length,!0),ie.currentPanel&&ie.currentPanel.updateFindings(c)});let a=()=>f.workspace.getConfiguration("secretLeakDetector");function d(){let l=a().get("minEntropy");e.setMinEntropy(typeof l=="number"&&l>0?l:void 0);let u=t.workspaceState.get("ignoredFindings",[]);e.setIgnoredFindings(u)}d();let p=q.join(t.extensionPath,"dist","cli.js");try{let c=t.globalStorageUri.fsPath;B.existsSync(c)||B.mkdirSync(c,{recursive:!0});let l=q.join(c,"cli.js");B.existsSync(p)&&(B.copyFileSync(p,l),p=l)}catch{}async function g(c){let l=f.workspace.workspaceFolders||[],u=a().get("blockGitCommits",!0),h=_e(a().get("failOn",M)),v=[];for(let b of l){let E=new X(b.uri.fsPath,m=>N.appendLine(m));await E.isGitRepo()&&(await E.ensureHookIsPinned(c,process.execPath,u,h).catch(()=>{}),v.push(q.join(b.uri.fsPath,".git","hooks","pre-commit")))}try{let b=q.join(t.globalStorageUri.fsPath,"installed-hooks.json");B.writeFileSync(b,JSON.stringify(v,null,2),"utf8")}catch{}}B.existsSync(p)&&g(p).catch(()=>{}),t.subscriptions.push(f.workspace.onDidChangeWorkspaceFolders(async()=>{B.existsSync(p)&&await g(p).catch(()=>{})})),t.subscriptions.push(f.workspace.onDidChangeConfiguration(c=>{c.affectsConfiguration("secretLeakDetector")&&(d(),B.existsSync(p)&&g(p).catch(()=>{}),f.window.activeTextEditor&&e.scanDocument(f.window.activeTextEditor.document))})),f.window.activeTextEditor&&e.scanDocument(f.window.activeTextEditor.document),t.subscriptions.push(f.workspace.onDidSaveTextDocument(c=>{a().get("enableRealtimeScanning",!0)&&e.scanDocument(c)})),t.subscriptions.push(f.workspace.onDidOpenTextDocument(c=>{a().get("enableRealtimeScanning",!0)&&e.scanDocument(c)})),t.subscriptions.push(f.workspace.onDidChangeTextDocument(c=>{if(!a().get("enableRealtimeScanning",!0))return;let l=c.document.uri.toString(),u=me.get(l);u&&clearTimeout(u);let h=setTimeout(()=>{e.scanDocument(c.document),me.delete(l)},350);me.set(l,h)})),t.subscriptions.push(f.workspace.onDidDeleteFiles(c=>{c.files.forEach(l=>e.removeDocument(l))})),t.subscriptions.push(f.workspace.onDidRenameFiles(c=>{c.files.forEach(l=>e.renameDocument(l.oldUri,l.newUri))})),t.subscriptions.push(f.commands.registerCommand("secret-leak-detector.scanWorkspace",async()=>{await f.window.withProgress({location:f.ProgressLocation.Notification,title:"\u{1F510} Scanning workspace for secret leaks...",cancellable:!0},async(c,l)=>{let u=a().get("excludeGlobs",[]),h=u.length>0?`{${u.join(",")}}`:void 0,v=1e3,b=await f.workspace.findFiles("**/*",h,v),E=new Map,m=[],C=0,_=0,L=b.length;for(let I=0;I<L;I++){if(l.isCancellationRequested){f.window.showInformationMessage("Secret Leak Detector: Workspace scan was cancelled.");return}let x=b[I],T=q.extname(x.fsPath).toLowerCase();if(Ie.has(T)){_++;continue}try{if((await f.workspace.fs.stat(x)).size>5*1024*1024){_++;continue}let Q=await f.workspace.fs.readFile(x),se=Buffer.from(Q).toString("utf8"),H=f.workspace.getWorkspaceFolder(x),U={workspaceRoot:H?H.uri.fsPath:void 0,minEntropyThreshold:a().get("minEntropy")},ee=re(se,x.fsPath,U);E.set(x.fsPath,ee),m.push(...ee),C++}catch{_++}c.report({message:`${C}/${L} files scanned`,increment:1/(L||1)*100})}e.setBatchFindings(E);let W=b.length>=v,k=`Scanned ${C} files.`;W&&(k+=` \u26A0\uFE0F Scan was capped at ${v} files.`),_>0&&(k+=` (${_} large or binary files skipped)`);let S=new Set(e.getIgnoredFindings()),y=m.filter(I=>!S.has(I.id));if(C===0)f.window.showWarningMessage(`\u26A0\uFE0F Workspace scan complete: 0 files were scanned. ${k}`);else if(y.length===0)f.window.showInformationMessage(`\u2705 Scan complete: ${k} No unignored secrets or credentials detected!`);else{let I=y.filter(x=>x.risk==="CRITICAL").length;f.window.showErrorMessage(`\u{1F6A8} Found ${y.length} leaked secret(s) (${I} Critical)! ${k}`,"Open Dashboard","View Findings").then(x=>{x==="Open Dashboard"?f.commands.executeCommand("secret-leak-detector.openDashboard"):x==="View Findings"&&f.commands.executeCommand("workbench.view.extension.secret-leak-detector-sidebar")})}})})),t.subscriptions.push(f.commands.registerCommand("secret-leak-detector.scanStaged",async()=>{N.clear(),N.appendLine("\u{1F510} [Secret Leak Detector] Scanning Git staged changes..."),N.show(!0);let c=a().get("blockGitCommits",!0),l=_e(a().get("failOn",M)),u=f.workspace.workspaceFolders||[],h=new Set;for(let k of u)await new X(k.uri.fsPath).isGitRepo()&&h.add(k.uri.fsPath);h.size===0&&h.add(r);let v=[],b=[],E=[];for(let k of h){let y=await new X(k,I=>N.appendLine(I)).scanStagedChanges();y.status==="ERROR"&&E.push(`${k}: ${y.error}`),y.skippedFiles&&b.push(...y.skippedFiles),y.findings&&v.push(...y.findings)}if(E.length>0){let k=`\u274C Git scan encountered error(s):
${E.join(`
`)}`;if(N.appendLine(k),f.window.showErrorMessage(k,"View Output").then(S=>{S==="View Output"&&N.show(!0)}),c)return}if(b.length>0){N.appendLine(`\u2139\uFE0F  Skipped ${b.length} binary or oversized file(s):`);for(let k of b)N.appendLine(`   \u2022 ${k.path}: ${k.reason}`)}if(v.length===0){N.appendLine("\u2705 All staged changes are clean! No credentials detected."),f.window.showInformationMessage("\u2705 Git staged changes are safe to commit.");return}let m=v.filter(k=>Et(k.risk,l)),_=new X(r).formatTerminalBlockedMessage(m.length>0?m:v);N.appendLine(_);let W=c&&m.length>0?`\u274C COMMIT BLOCKED: ${m.length} secret(s) at or above ${l} detected in staged changes!`:`\u26A0\uFE0F WARNING: ${v.length} secret(s) detected in staged changes (none block at the ${l} threshold).`;f.window.showErrorMessage(W,"Open Dashboard","View Output").then(k=>{k==="Open Dashboard"?ie.createOrShow(t.extensionUri,v):k==="View Output"&&N.show(!0)})})),t.subscriptions.push(f.commands.registerCommand("secret-leak-detector.openDashboard",()=>{ie.createOrShow(t.extensionUri,e.getAllFindings())})),t.subscriptions.push(f.commands.registerCommand("secret-leak-detector.installGitHook",async()=>{let c=a().get("blockGitCommits",!0),l=_e(a().get("failOn",M)),u=await o.installPreCommitHook(p,process.execPath,c,l);u.success?f.window.showInformationMessage(`\u{1F6E1}\uFE0F ${u.message}`):f.window.showErrorMessage(`Failed to install hook: ${u.message}`)})),t.subscriptions.push(f.commands.registerCommand("secret-leak-detector.uninstallGitHook",async()=>{let c=await o.uninstallPreCommitHook();c.success?f.window.showInformationMessage(`\u{1F6E1}\uFE0F ${c.message}`):f.window.showErrorMessage(`Failed to uninstall hook: ${c.message}`)})),t.subscriptions.push(f.commands.registerCommand("secret-leak-detector.ignoreFinding",async c=>{let l=c;if(!l){let b=e.getAllFindings();if(b.length===0){f.window.showInformationMessage("No active findings to ignore.");return}let E=await f.window.showQuickPick(b.map(m=>({label:`${m.type} (${m.file}:${m.line})`,description:m.redactedSecret,id:m.id})),{placeHolder:"Select a finding to ignore (suppress as false-positive)"});if(!E)return;l=E.id}e.ignoreFinding(l);let u=e.getIgnoredFindings();await t.workspaceState.update("ignoredFindings",u);let v=e.getAllFindings().find(b=>b.id===l);if(v){let b=t.workspaceState.get("ignoredFindingsMeta",{});b[l]={type:v.type,file:v.file,line:v.line,secret:v.redactedSecret},await t.workspaceState.update("ignoredFindingsMeta",b)}f.window.showInformationMessage("\u{1F6E1}\uFE0F Finding marked as false-positive and suppressed.")})),t.subscriptions.push(f.commands.registerCommand("secret-leak-detector.unignoreFinding",async()=>{let c=e.getIgnoredFindings();if(c.length===0){f.window.showInformationMessage("No suppressed findings to restore.");return}let l=t.workspaceState.get("ignoredFindingsMeta",{}),u=c.map(b=>{let E=l[b];return{label:E?`${E.type} (${E.secret})`:b,description:E?`${q.basename(E.file)}:${E.line}`:void 0,detail:E?E.file:b,id:b}}),h=await f.window.showQuickPick(u,{placeHolder:"Select a suppressed finding to restore"});if(!h)return;let v=c.filter(b=>b!==h.id);e.setIgnoredFindings(v),await t.workspaceState.update("ignoredFindings",v),delete l[h.id],await t.workspaceState.update("ignoredFindingsMeta",l),f.window.activeTextEditor&&e.scanDocument(f.window.activeTextEditor.document),f.window.showInformationMessage(`\u{1F6E1}\uFE0F Restored finding '${h.label}'.`)})),t.subscriptions.push(f.commands.registerCommand("secret-leak-detector.remediateFinding",async(c,l,u)=>{await ae.executeRemediation(c,l,u)})),t.subscriptions.push(f.commands.registerCommand("secret-leak-detector.clearFindings",()=>{e.clear(),f.window.showInformationMessage("Secret Leak Detector: All findings cleared.")})),o.isGitRepo().then(c=>{i.update(0,c)})}function an(){for(let t of me.values())clearTimeout(t);me.clear()}0&&(module.exports={activate,deactivate});
