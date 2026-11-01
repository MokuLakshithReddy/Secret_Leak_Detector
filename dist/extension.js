"use strict";var St=Object.create;var pe=Object.defineProperty;var Et=Object.getOwnPropertyDescriptor;var xt=Object.getOwnPropertyNames;var Ct=Object.getPrototypeOf,It=Object.prototype.hasOwnProperty;var wt=(t,e)=>{for(var i in e)pe(t,i,{get:e[i],enumerable:!0})},$e=(t,e,i,n)=>{if(e&&typeof e=="object"||typeof e=="function")for(let s of xt(e))!It.call(t,s)&&s!==i&&pe(t,s,{get:()=>e[s],enumerable:!(n=Et(e,s))||n.enumerable});return t};var I=(t,e,i)=>(i=t!=null?St(Ct(t)):{},$e(e||!t||!t.__esModule?pe(i,"default",{value:t,enumerable:!0}):i,t)),Rt=t=>$e(pe({},"__esModule",{value:!0}),t);var Vt={};wt(Vt,{activate:()=>Ht,deactivate:()=>Gt});module.exports=Rt(Vt);var m=I(require("vscode")),yt=I(require("path")),kt=I(require("fs"));var _=I(require("vscode"));var X=I(require("path")),st=I(require("crypto"));var Le=[{id:"aws-access-key",name:"AWS Access Key ID",provider:"Amazon Web Services",pattern:/\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b/g,baseConfidence:98,baseRiskWeight:95,signals:["AWS IAM standard 20-character key prefix (AKIA/ASIA/ABIA/ACCA)","Deterministic uppercase alphanumeric structure","Direct cloud resource control & hijacking capability"],suggestedEnvName:()=>"AWS_ACCESS_KEY_ID",remediationInstructions:["Revoke the exposed Access Key ID immediately in AWS IAM Management Console.","Check AWS CloudTrail logs for unauthorized API calls originated by this key.","Transition to IAM Roles for Amazon EC2 or AWS IAM Identity Center (SSO).","Never store access keys in source code; use AWS_ACCESS_KEY_ID environment variable."]},{id:"aws-secret-key",name:"AWS Secret Access Key",provider:"Amazon Web Services",pattern:/["']?(?:aws_secret_access_key|aws_secret_key|secret_access_key)["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?(?:[\s\r\n;,)]|$)/gi,baseConfidence:94,baseRiskWeight:95,minEntropy:4.1,signals:["Contextual AWS credential parameter match","High-entropy 40-character Base64 payload","Pairs with AWS Access Key for root/IAM API authentication"],suggestedEnvName:()=>"AWS_SECRET_ACCESS_KEY",remediationInstructions:["Rotate the key pair immediately in the AWS IAM Console.","Audit AWS KMS and S3 bucket accesses during exposure window.","Store secrets in AWS Secrets Manager or Parameter Store."]},{id:"github-pat",name:"GitHub Personal Access Token",provider:"GitHub",pattern:/\b(gh[pousr]_[A-Za-z0-9_]{36,255}|github_pat_[A-Za-z0-9_]{82})\b/g,baseConfidence:99,baseRiskWeight:95,signals:["Official GitHub token format prefix (ghp_, gho_, ghu_, ghs_, github_pat_)","Deterministic token structure and length","Permits repository code modification, workflow execution, or release poisoning"],suggestedEnvName:()=>"GITHUB_TOKEN",remediationInstructions:["Revoke token immediately at https://github.com/settings/tokens.","Check GitHub Security Audit Log for unauthorized repository clones or writes.","Use GitHub fine-grained PATs with scoped repository permissions.","Use GitHub Actions secrets rather than personal tokens for CI/CD."]},{id:"google-api-key",name:"Google Cloud / Gemini API Key",provider:"Google Cloud",pattern:/\b(AIza[0-9A-Za-z_-]{34,35})\b/g,baseConfidence:96,baseRiskWeight:90,minEntropy:3.5,signals:["Google standard AIza service key signature","Fixed 39-character alphanumeric structure","Access to Google Cloud Platform APIs and billing services"],suggestedEnvName:()=>"GEMINI_API_KEY",remediationInstructions:["Restrict or delete the API key in Google Cloud Console Credentials page.","Apply API restrictions (e.g. restrict solely to Generative Language API).","Apply HTTP referrer or IP address restrictions.","Store in GEMINI_API_KEY environment variable."]},{id:"google-oauth-token",name:"Google OAuth Access Token",provider:"Google Cloud",pattern:/\b(ya29\.[0-9a-zA-Z_-]{50,150})\b/g,baseConfidence:98,baseRiskWeight:92,minEntropy:4,signals:["Google OAuth bearer access token prefix (ya29.)","Direct user account delegation & Cloud Platform API access"],suggestedEnvName:()=>"GOOGLE_OAUTH_TOKEN",remediationInstructions:["Revoke token via Google Cloud IAM or OAuth2 token revocation endpoint.","Store OAuth refresh tokens securely in credential vaults."]},{id:"openai-api-key",name:"OpenAI API Key",provider:"OpenAI",pattern:/\b(sk-(?:proj|admin|svcacct)-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{20,48})\b/g,baseConfidence:97,baseRiskWeight:92,minEntropy:4,signals:["OpenAI official secret prefix (sk-proj- or sk-)","High Shannon entropy key payload","Direct account credit exhaustion and model theft risk"],suggestedEnvName:()=>"OPENAI_API_KEY",remediationInstructions:["Revoke key at https://platform.openai.com/api-keys.","Verify credit consumption in OpenAI usage dashboard.","Inject credentials using OPENAI_API_KEY environment variable."]},{id:"anthropic-api-key",name:"Anthropic Claude API Key",provider:"Anthropic",pattern:/\b(sk-ant-[A-Za-z0-9_-]{30,})\b/g,baseConfidence:98,baseRiskWeight:92,minEntropy:3.8,signals:["Anthropic official secret token signature (sk-ant-)","High entropy cryptographic token payload","Direct Claude model API billing access"],suggestedEnvName:()=>"ANTHROPIC_API_KEY",remediationInstructions:["Revoke the API key in Anthropic Console.","Generate replacement key with spend limit configured.","Inject via ANTHROPIC_API_KEY environment variable."]},{id:"huggingface-token",name:"Hugging Face Access Token",provider:"Hugging Face",pattern:/\b(hf_[A-Za-z0-9]{34})\b/g,baseConfidence:98,baseRiskWeight:88,minEntropy:3.8,signals:["Hugging Face user access token format (hf_ prefix + 34 chars)","Grants access to gated AI models, private repositories, and inference endpoints"],suggestedEnvName:()=>"HF_TOKEN",remediationInstructions:["Revoke token immediately at https://huggingface.co/settings/tokens.","Audit access logs for unauthorized model downloads.","Inject credentials using the HF_TOKEN environment variable."]},{id:"stripe-secret-key",name:"Stripe Secret Key",provider:"Stripe",pattern:/\b((?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,100})\b/g,baseConfidence:97,baseRiskWeight:96,signals:["Stripe signature prefix (sk_live / rk_live / sk_test)","Financial transaction and customer credit card access","High financial liability and compliance breach"],suggestedEnvName:()=>"STRIPE_SECRET_KEY",remediationInstructions:["Roll API key immediately in Stripe Dashboard > Developers > API keys.","Audit recent transactions and payout bank account modifications.","Never bundle Stripe secret keys in frontend or mobile client builds."]},{id:"slack-bot-token",name:"Slack OAuth / Bot Token",provider:"Slack",pattern:/\b(xox[baprs]-[0-9A-Za-z-]{10,72})\b/g,baseConfidence:95,baseRiskWeight:82,signals:["Slack OAuth bot/user prefix (xoxb/xoxp/xoxa)","Internal company communications and workspace access"],suggestedEnvName:()=>"SLACK_BOT_TOKEN",remediationInstructions:["Revoke token in api.slack.com/apps.","Re-install app with minimal necessary OAuth scopes."]},{id:"slack-webhook",name:"Slack Incoming Webhook URL",provider:"Slack",pattern:/(https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9_]{8,12}\/B[A-Z0-9_]{8,12}\/[A-Za-z0-9_]{24})/g,baseConfidence:98,baseRiskWeight:78,signals:["Slack Incoming Webhook URL structure","Enables unauthorized message spoofing and channel phishing"],suggestedEnvName:()=>"SLACK_WEBHOOK_URL",remediationInstructions:["Delete the exposed webhook URL in Slack App settings.","Generate a new webhook URL and store in SLACK_WEBHOOK_URL."]},{id:"azure-storage-key",name:"Azure Shared Storage Key",provider:"Microsoft Azure",pattern:/["']?(?:AccountKey|azure_secret|azure_key)["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{86,88}==)(?:["';,\s\r\n)]|$)/gi,baseConfidence:93,baseRiskWeight:90,minEntropy:4.2,signals:["Azure storage account key signature (86-88 chars base64 with == padding)","Full administrative access to Azure Blob/Queue/Table storage"],suggestedEnvName:()=>"AZURE_STORAGE_KEY",remediationInstructions:["Regenerate storage key in Azure Portal.","Adopt Azure Managed Identity or Microsoft Entra ID authentication instead."]},{id:"azure-ad-client-secret",name:"Azure Active Directory Client Secret",provider:"Microsoft Azure",pattern:/["']?(?:azure[_-]?(?:client|ad|app)?[_-]?secret|client[_-]?secret)\s*[:=]\s*["']?([a-zA-Z0-9_~.-]{34,44})["']?(?:[\s\r\n;,)]|$)/gi,baseConfidence:90,baseRiskWeight:90,minEntropy:3.8,signals:["Azure AD / Entra ID client secret assignment pattern","Application impersonation and tenant directory access"],suggestedEnvName:()=>"AZURE_CLIENT_SECRET",remediationInstructions:["Revoke and rotate the client secret in Azure App Registrations portal.","Migrate to Managed Identity or Federated Credentials where possible."]},{id:"discord-bot-token",name:"Discord Bot Token",provider:"Discord",pattern:/\b([M-Z][A-Za-z0-9]{23,27}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,38})\b/g,baseConfidence:98,baseRiskWeight:88,signals:["Official Discord bot token format (ID.HMAC.Signature)","Complete bot control, server membership manipulation, and message reading"],suggestedEnvName:()=>"DISCORD_BOT_TOKEN",remediationInstructions:["Reset token in Discord Developer Portal > Bot > Reset Token.","Store in DISCORD_BOT_TOKEN environment variable."]},{id:"telegram-bot-token",name:"Telegram Bot Token",provider:"Telegram",pattern:/\b([0-9]{8,10}:[a-zA-Z0-9_-]{35})\b/g,baseConfidence:96,baseRiskWeight:85,signals:["Telegram Bot API token format (Numeric ID : 35-character secret)","Direct control of Telegram bot communications and webhooks"],suggestedEnvName:()=>"TELEGRAM_BOT_TOKEN",remediationInstructions:["Revoke and reissue the token using Telegram @BotFather (/revoke).","Store in TELEGRAM_BOT_TOKEN environment variable."]},{id:"pypi-api-token",name:"PyPI API Token",provider:"PyPI",pattern:/\b(pypi-[A-Za-z0-9_-]{50,150})\b/g,baseConfidence:99,baseRiskWeight:92,signals:["Official PyPI package index upload token prefix (pypi-)","Supply chain compromise and malicious Python package publication risk"],suggestedEnvName:()=>"PYPI_TOKEN",remediationInstructions:["Revoke the token immediately at https://pypi.org/manage/account/tokens/.","Inspect published package versions for tampering."]},{id:"shopify-access-token",name:"Shopify Admin / Storefront Access Token",provider:"Shopify",pattern:/\b(shp(?:at|ca|pa)_[a-fA-F0-9]{32})\b/g,baseConfidence:98,baseRiskWeight:92,signals:["Official Shopify access token prefix (shpat_, shpca_, shppa_)","E-commerce store data, customer orders, and payment configuration access"],suggestedEnvName:()=>"SHOPIFY_API_KEY",remediationInstructions:["Revoke the token in Shopify Admin > Apps and sales channels.","Audit store access and customer data logs."]},{id:"digitalocean-pat",name:"DigitalOcean Personal Access Token",provider:"DigitalOcean",pattern:/\b(dop_v1_[a-f0-9]{64})\b/g,baseConfidence:99,baseRiskWeight:92,signals:["Official DigitalOcean v1 token format (dop_v1_ prefix + 64 hex characters)","Droplet creation, destruction, and Cloud infrastructure control"],suggestedEnvName:()=>"DIGITALOCEAN_TOKEN",remediationInstructions:["Revoke the token in DigitalOcean Control Panel > API > Tokens.","Check active Droplets and firewall configurations for unauthorized changes."]},{id:"mailgun-api-key",name:"Mailgun Private API Key",provider:"Mailgun",pattern:/\b(key-[0-9a-zA-Z]{32})\b/g,baseConfidence:96,baseRiskWeight:85,signals:["Mailgun standard private API key signature (key- + 32 chars)","Bulk email dispatch and communication channel spoofing"],suggestedEnvName:()=>"MAILGUN_API_KEY",remediationInstructions:["Rotate key in Mailgun Dashboard > API Security.","Store in MAILGUN_API_KEY environment variable."]},{id:"square-access-token",name:"Square Access Token",provider:"Square",pattern:/\b(sq0atp-[0-9A-Za-z_-]{22}|sq0csp-[0-9A-Za-z_-]{43}|EAAA[a-zA-Z0-9_-]{60})\b/g,baseConfidence:97,baseRiskWeight:94,signals:["Square OAuth / production access token prefix (sq0atp-, sq0csp-, EAAA)","Payment processing, merchant account, and customer financial data access"],suggestedEnvName:()=>"SQUARE_ACCESS_TOKEN",remediationInstructions:["Revoke token in Square Developer Dashboard > OAuth settings.","Audit payment ledger and API access history."]},{id:"private-key",name:"Cryptographic Private Key (PEM)",provider:"Cryptography",pattern:/(-----BEGIN (?:[A-Z0-9_-]+ )*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END (?:[A-Z0-9_-]+ )*PRIVATE KEY(?: BLOCK)?-----)/g,baseConfidence:100,baseRiskWeight:100,signals:["Standard PEM container header and footer","Unencrypted cryptographic private key","Total server impersonation, SSH compromise, or TLS decryption risk"],suggestedEnvName:()=>"PRIVATE_KEY_PATH",remediationInstructions:["Immediately decommission this private key pair.","Remove public key counterpart from all servers authorized_keys.","Never commit private keys to version control; use SSH agents or secret vaults."]},{id:"database-url",name:"Database Connection String with Credentials",provider:"Database",pattern:/\b((?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis):\/\/[^:\s'"@]+:([^@\s'"]+)@([a-zA-Z0-9_.-]+(?::[0-9]+)?(?:\/[^\s'"`;]*)?))/gi,baseConfidence:92,baseRiskWeight:88,minEntropy:3.2,signals:["Database connection URL containing embedded user:password credentials","Direct data exfiltration, deletion, or ransomware risk"],suggestedEnvName:()=>"DATABASE_URL",remediationInstructions:["Rotate the database user password immediately on the database server.","Migrate connection string to DATABASE_URL environment variable.","Enable SSL/TLS requirement and VPC network access controls."]},{id:"url-credentials",name:"URL with Embedded Credentials",provider:"Generic Credential",pattern:/\b(https?:\/\/[^:\s'"\/?#@]+:([^@\s'"\/?#]+)@([a-zA-Z0-9_.-]+(?::[0-9]+)?(?:\/[^\s'"`;]*)?))/gi,baseConfidence:90,baseRiskWeight:85,minEntropy:3,signals:["HTTP/HTTPS URL containing embedded user:password or user:token credentials","Authentication credential transmission in URL plain text"],suggestedEnvName:()=>"API_ENDPOINT_URL",remediationInstructions:["Remove credentials from URL; pass authentication in Authorization headers.","Rotate exposed password or access token immediately."]},{id:"bearer-token",name:"Authorization Bearer Token",provider:"Auth / Identity",pattern:/(?:Authorization|auth)\s*[:=]\s*["']?Bearer\s+([A-Za-z0-9_.~+/-]{20,255})["']?/gi,baseConfidence:92,baseRiskWeight:85,minEntropy:3.5,signals:["HTTP Authorization header with static Bearer token literal","API session impersonation and service authentication bypass"],suggestedEnvName:()=>"AUTH_TOKEN",remediationInstructions:["Revoke the exposed bearer token.","Inject bearer tokens dynamically from environment variables."]},{id:"jwt-token",name:"JSON Web Token (JWT)",provider:"Auth / Identity",pattern:/\b(ey[A-Za-z0-9_-]{15,}\.ey[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{10,})\b/g,baseConfidence:88,baseRiskWeight:75,minEntropy:4.1,signals:["Header.Payload.Signature Base64 tripartite JWT structure","Authentication session hijacking and privilege escalation"],suggestedEnvName:t=>t?.toUpperCase()||"AUTH_TOKEN",remediationInstructions:["Invalidate active sessions / revoke refresh token family in identity provider.","Never hardcode tokens in client or backend source repositories."]},{id:"gitlab-pat",name:"GitLab Personal Access Token",provider:"GitLab",pattern:/\b(glpat-[0-9a-zA-Z_-]{20,40})\b/g,baseConfidence:98,baseRiskWeight:90,signals:["GitLab personal access token prefix (glpat-)","Repository read/write and CI/CD control"],suggestedEnvName:()=>"GITLAB_TOKEN",remediationInstructions:["Revoke token in GitLab User Settings > Access Tokens.","Store in GITLAB_TOKEN environment variable."]},{id:"npm-access-token",name:"npm Access Token",provider:"npm",pattern:/\b(npm_[A-Za-z0-9]{36})\b/g,baseConfidence:99,baseRiskWeight:92,signals:["npm official access token prefix (npm_)","Package publication and account takeover capability"],suggestedEnvName:()=>"NPM_TOKEN",remediationInstructions:["Revoke token immediately at https://www.npmjs.com/settings/tokens.","Store in NPM_TOKEN environment variable."]},{id:"sendgrid-api-key",name:"SendGrid API Key",provider:"SendGrid",pattern:/\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b/g,baseConfidence:99,baseRiskWeight:85,signals:["SendGrid standard tripartite API key (SG.<22>.<43>)","Email spoofing and communication channel hijacking risk"],suggestedEnvName:()=>"SENDGRID_API_KEY",remediationInstructions:["Revoke key in SendGrid dashboard Settings > API Keys.","Store in SENDGRID_API_KEY environment variable."]},{id:"twilio-api-key",name:"Twilio Auth Token / API Secret",provider:"Twilio",pattern:/\b(SK[0-9a-fA-F]{32})\b|["']?(?:twilio[a-z0-9_-]*(?:auth_?token|api_?secret|secret)|(?:auth_?token|api_?secret))\s*[:=]\s*["']?([0-9a-fA-F]{32})["']?(?:[\s\r\n;,)]|$)/gi,baseConfidence:95,baseRiskWeight:90,minEntropy:3.5,signals:["Twilio Auth Token, API Key SID (SK...), or API Secret assignment","32-character hexadecimal secret token","Telephony API and SMS billing access"],suggestedEnvName:()=>"TWILIO_AUTH_TOKEN",remediationInstructions:["Rotate token in Twilio Console.","Store in TWILIO_AUTH_TOKEN environment variable."]},{id:"password-assignment",name:"Password in Source Code",provider:"Generic Credential",pattern:/["']?(?:password|passwd|pwd|db_password|db_pass)["']?\s*[:=]\s*["']?(?!(?:password|passwordRequired|required|required_field|true|false|null|undefined|string|default|changeme|placeholder|example|admin|test)\b)([^"'\r\n\s#;,]{8,64})["']?/gi,baseConfidence:82,baseRiskWeight:80,minEntropy:2.8,signals:["Hard-coded password assignment in code, .env, or YAML","Credential exposure in plain text"],suggestedEnvName:()=>"PASSWORD",remediationInstructions:["Rotate password immediately.","Store password in an environment variable or secrets manager.","Never commit plain passwords to version control."]},{id:"generic-api-key",name:"Generic API Secret Assignment",provider:"Generic Credential",pattern:/["']?(?:api_?key|secret_?key|auth_?token|client_?secret|access_?token|private_?key|jwt_?secret)["']?\s*[:=]\s*["']?(?!(?:process\.env|import\.meta\.env|os\.environ|ENV)\b)([A-Za-z0-9_.~/+=]{20,90})["']?(?:[\s\r\n;,)]|$)/gi,baseConfidence:80,baseRiskWeight:70,minEntropy:3.5,signals:["Sensitive identifier keyword assignment in code, .env, or YAML","High Shannon entropy string literal"],suggestedEnvName:t=>t?t.toUpperCase():"API_KEY",remediationInstructions:["Identify corresponding API provider and rotate credential.","Migrate credential to local .env file (ensure .env is in .gitignore)."]}];var K=I(require("path")),_t=[/api[_-]?key/i,/secret[_-]?key/i,/access[_-]?token/i,/auth[_-]?token/i,/private[_-]?key/i,/client[_-]?secret/i,/password/i,/credential/i,/session[_-]?token/i,/bearer/i,/aws[_-]?(?:access|secret)/i,/stripe[_-]?(?:secret|key)/i,/github[_-]?(?:token|pat)/i,/slack[_-]?token/i,/db[_-]?pass(?:word)?/i],Tt=[/placeholder/i,/mock/i,/dummy/i,/fake/i,/sample/i,/test[_-]?(?:key|token|id)/i,/demo/i,/insert[_-]?here/i];function Pt(t,e){if(e){let i=K.relative(e,t);if(!i.startsWith("..")&&!K.isAbsolute(i))return i.replace(/\\/g,"/")}return K.isAbsolute(t)?K.basename(t):t.replace(/\\/g,"/")}function Oe(t,e){let i=Pt(t,e).toLowerCase(),n=K.basename(t).toLowerCase(),s=K.extname(t).toLowerCase(),o=/(?:^|\/)(?:tests?|specs?|__tests__|__mocks__|fixtures|mocks)\//i.test(i)||/[._-](?:test|spec)\.[a-z0-9]+$/i.test(n)||/^(?:test|spec)\.[a-z0-9]+$/i.test(n),r=/(?:^|\/)(?:docs|doc|documentation|tutorials|guides)\/|readme\.md|contributing\.md|changelog\.md/i.test(i),c=/(?:^|\/)(?:example|sample|\.example|\.sample)/i.test(i)||/[._-](?:example|sample)\.[a-z0-9]+$/i.test(n),d=/^\.env(?:\.[a-z0-9]+)?$/.test(n)||/(?:^|\/)(?:config|settings|k8s|helm|deploy|tfvars)\//i.test(i)||/(?:^|[._-])(?:config|settings|secret|credential|database|deploy)\.[a-z0-9]+$/i.test(n)||[".env",".yaml",".yml",".json",".toml",".ini",".tf"].includes(s),l=/^\.env/.test(n)||/(?:secret|credential|id_rsa|private_key|keypair|auth_config)/i.test(n);return{fileExtension:s,isConfig:d,isTest:o,isDoc:r,isSensitiveName:l,isExampleOrSample:c}}function Se(t,e){let i=t[e]||"",n=[];for(let f=Math.max(0,e-3);f<e;f++)n.push(t[f]);let s=[];for(let f=e+1;f<Math.min(t.length,e+4);f++)s.push(t[f]);let o,r=i.match(/(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*[:=]/),c=i.match(/["']?([a-zA-Z0-9_$-]+)["']?\s*[:=]/);r?o=r[1]:c&&(o=c[1]);let d=o?_t.some(f=>f.test(o)):!1,l=o?Tt.some(f=>f.test(o)):!1,u=/[:=]/.test(i),a=/(?:process\.env|os\.environ|dotenv|config|getenv)/i.test(i),p=/(?:authorization|bearer|x-api-key)/i.test(i),g=/^\s*(?:\/\/|#|\/\*|\*|--)/.test(i);return{inferredVariable:o,isSensitiveIdentifier:d,isBenignIdentifier:l,isAssignment:u,isEnvOrConfigAccess:a,isHeaderOrBearer:p,isInComment:g,surroundingBefore:n,matchedLine:i,surroundingAfter:s}}var ue=/(?:api_?key|secret|token|password|auth|credential|access_?key|private_?key)/i,Ne=/(?:console\.(?:log|warn|error|info|debug)|logger\.|print\(|logging\.)/i,ge=null;try{ge=require("typescript")}catch{ge=null}function Ee(t,e,i){let n=t[e]||"";if(ge&&(!i||/\.[jt]sx?$|\.m[jt]s$|\.c[jt]s$/i.test(i))){let o,r;if(t.length>60){let d=Math.max(0,e-30),l=Math.min(t.length,e+30);o=t.slice(d,l).join(`
`),r=e-d}else o=t.join(`
`),r=e;let c=Ft(o,r);if(c)return c}return Dt(n)}function Ft(t,e){try{let l=function(u){if(!d&&!(u.pos>c||u.end<r)&&(n.forEachChild(u,l),!d)){if(u.kind===n.SyntaxKind.BinaryExpression&&(u.operatorToken.kind===n.SyntaxKind.BarBarToken||u.operatorToken.kind===n.SyntaxKind.QuestionQuestionToken)){let a=u.left.getText(s);if(a.includes("process.env")||a.includes("env")||a.toLowerCase().includes("key")){d={variablePath:a,isSensitiveProperty:ue.test(a),isEnvFallback:!0,isAuthorizationHeader:!1,isLoggingCall:!1,scopeType:"ENV_FALLBACK"};return}}if(u.kind===n.SyntaxKind.PropertyAssignment){let a=u.name.getText(s),p=a,g=u.parent;for(;g;)g.kind===n.SyntaxKind.PropertyAssignment&&g.name?p=`${g.name.getText(s)}.${p}`:g.kind===n.SyntaxKind.VariableDeclaration&&g.name&&(p=`${g.name.getText(s)}.${p}`),g=g.parent;let f=ue.test(p),h=/authorization|bearer|x-api-key/i.test(a);d={variablePath:p,isSensitiveProperty:f,isEnvFallback:!1,isAuthorizationHeader:h,isLoggingCall:!1,scopeType:h?"HEADER":"OBJECT_PROPERTY"};return}if(u.kind===n.SyntaxKind.CallExpression){let a=u.expression.getText(s);if(Ne.test(a)){d={variablePath:a,isSensitiveProperty:!1,isEnvFallback:!1,isAuthorizationHeader:!1,isLoggingCall:!0,scopeType:"FUNCTION_ARG"};return}}if(u.kind===n.SyntaxKind.VariableDeclaration){let a=u.name.getText(s);d={variablePath:a,isSensitiveProperty:ue.test(a),isEnvFallback:!1,isAuthorizationHeader:!1,isLoggingCall:!1,scopeType:"VARIABLE_DECLARATION"};return}}};var i=l;let n=ge,s=n.createSourceFile("eval_target.tsx",t,n.ScriptTarget.Latest,!0,n.ScriptKind.TSX),o=s.getLineStarts();if(e>=o.length)return null;let r=o[e],c=e+1<o.length?o[e+1]-1:t.length,d=null;return l(s),d}catch{return null}}function Dt(t){let e=Ne.test(t),i=/(?:process\.env\.[A-Za-z0-9_]+|os\.(?:getenv|environ\.get)\([^)]+\))\s*(?:\|\||\?\?)\s*["'][^"']+["']/.test(t),n=/(?:authorization|x-api-key|bearer)\s*[:=]/i.test(t),s=t.match(/([a-zA-Z0-9_$.]+)\s*[:=]\s*["'][^"']+["']/)||t.match(/["']([a-zA-Z0-9_.]+)["']\s*:\s*["'][^"']+["']/),o,r=!1;s&&(o=s[1],r=ue.test(o));let c="UNKNOWN";return i?c="ENV_FALLBACK":n?c="HEADER":o&&o.includes(".")?c="OBJECT_PROPERTY":o?c="VARIABLE_DECLARATION":e&&(c="FUNCTION_ARG"),{variablePath:o,isSensitiveProperty:r,isEnvFallback:i,isAuthorizationHeader:n,isLoggingCall:e,scopeType:c}}function se(t){if(!t||t.length===0)return 0;let e={};for(let s of t)e[s]=(e[s]||0)+1;let i=0,n=t.length;for(let s in e){let o=e[s]/n;i-=o*Math.log2(o)}return Math.round(i*100)/100}function xe(t){return/^[0-9a-fA-F]+$/.test(t)?{setName:"HEX",baseSize:16}:/^[A-Za-z0-9+/=_-]+$/.test(t)?{setName:"BASE64",baseSize:64}:/^[A-Za-z0-9]+$/.test(t)?{setName:"ALPHANUMERIC",baseSize:62}:/^[\x20-\x7E]+$/.test(t)?{setName:"ASCII_PRINTABLE",baseSize:95}:{setName:"SPECIAL",baseSize:128}}function Me(t){if(!t||t.length===0)return 0;let e=se(t),{baseSize:i}=xe(t),n=Math.log2(i);if(n<=0)return 0;let s=Math.min(1,e/n);return Math.round(s*100)/100}var $t=[/\bplaceholder\b/i,/\byour[_-]?(?:api)?[_-]?key\b/i,/\byour[_-]?secret\b/i,/\byour[_-]?token\b/i,/\binsert[_-]?here\b/i,/\breplace[_-]?me\b/i,/\benter[_-]?your\b/i,/\bchange[_-]?me\b/i,/\bdummy\b/i,/\bfake[_-]?token\b/i,/xxxx+/i,/\btest[_-]?value\b/i,/AKIAIOSFODNN7EXAMPLE/i,/wJalrXUtnFEMI\/K7MDENG\/bPxRfiCYEXAMPLEKEY/i,/^123456789[0-9]*$/,/^abcdef[a-z0-9]*$/i,/00000000[0-9]*/,/sk_live_example/i,/ghp_example/i,/:\/\/[^:]+:(?:password|secret|changeme|pass|admin|test|postgres|root)@(?:localhost|127\.0\.0\.1)(?::\d+)?\b/i,/:\/\/(?:postgres|root):(postgres|root)@(?:localhost|127\.0\.0\.1)(?::\d+)?\b/i],Lt=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,Ot=/^(?:mock|dummy|placeholder|fake|sample)_(?:key|token|secret|password|pwd|cred)$/i;function Be(t,e,i){if(/(?:process\.env|import\.meta\.env|os\.environ|ENV[\[\.])/.test(t))return{isFalsePositive:!0,reason:"Environment variable lookup expression, not a hard-coded credential literal",confidencePenalty:100};if(/^(?:passwordRequired|required_field|required|optional|placeholder|changeme|default|test|dummy|example|string|undefined|null)$/i.test(t))return{isFalsePositive:!0,reason:"Common non-secret schema or form attribute value",confidencePenalty:100};for(let s of $t)if(s.test(t))return{isFalsePositive:!0,reason:`Matched known documentation/placeholder pattern: ${s.source}`,confidencePenalty:100};if(e&&Ot.test(e)&&!(t.startsWith("AKIA")||t.startsWith("ASIA")||t.startsWith("ghp_")||t.startsWith("gho_")||t.startsWith("ghu_")||t.startsWith("ghs_")||t.startsWith("ghr_")||t.startsWith("github_pat_")||t.startsWith("glpat-")||t.startsWith("sk_live_")||t.startsWith("rk_live_")||t.startsWith("xoxb-")||t.startsWith("xoxp-")||t.startsWith("xoxa-")||t.startsWith("xoxr-")||t.startsWith("pypi-")||t.startsWith("dop_v1_")||t.startsWith("shpat_")||t.startsWith("shpca_")||t.startsWith("shppa_")||t.startsWith("ya29.")||t.startsWith("key-")||t.startsWith("sq0atp-")||t.startsWith("sq0csp-")||/^SK[0-9a-fA-F]{32}$/.test(t)||t.includes("-----BEGIN")||t.length>=14&&se(t)>=3.6))return{isFalsePositive:!0,reason:`Variable identifier indicates placeholder: ${e}`,confidencePenalty:100};let n=new Set(t.split("")).size;if(t.length>=10&&n<=3)return{isFalsePositive:!0,reason:"Low character diversity (repetitive filler characters)",confidencePenalty:95};if(Lt.test(t)&&!e?.match(/secret|token|api_?key/i))return{isFalsePositive:!0,reason:"Standard UUID identifier without credential context",confidencePenalty:90};if(i){let s=/(?:docs|documentation|tutorials|guides)\/|readme\.md/i.test(i);if(/(?:example|sample|\.example|\.sample)/i.test(i)&&/example|your_/i.test(t))return{isFalsePositive:!0,reason:"Sample configuration value inside template/example file",confidencePenalty:90};if(s&&!t.startsWith("ghp_")&&!t.startsWith("AKIA"))return{isFalsePositive:!1,confidencePenalty:25}}return{isFalsePositive:!1,confidencePenalty:0}}function Ke(t){if(!/^(AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}$/.test(t))return{isValid:!1,confidenceBonus:0,reason:"Invalid AWS key length or character set"};let e=t.substring(0,4);return{isValid:!0,confidenceBonus:10,reason:{AKIA:"Standard permanent IAM user access key",ASIA:"Temporary STS session access key",ABIA:"AWS Backup access key",ACCA:"AWS CodeCommit access key"}[e]||"Valid AWS Access Key ID structure"}}function We(t){let e=/^sk_live_[0-9a-zA-Z]{24,100}$/.test(t)||/^rk_live_[0-9a-zA-Z]{24,100}$/.test(t),i=/^sk_test_[0-9a-zA-Z]{24,100}$/.test(t)||/^rk_test_[0-9a-zA-Z]{24,100}$/.test(t);return!e&&!i?{isValid:!1,confidenceBonus:0,reason:"Does not match official Stripe secret key format"}:{isValid:!0,confidenceBonus:e?12:5,reason:e?"Production live Stripe Secret Key":"Stripe Test API key"}}function ze(t){return/^ghp_[A-Za-z0-9_]{36}$/.test(t)?{isValid:!0,confidenceBonus:12,reason:"GitHub Personal Access Token (Classic)"}:/^gho_[A-Za-z0-9_]{36}$/.test(t)?{isValid:!0,confidenceBonus:10,reason:"GitHub OAuth Access Token"}:/^ghs_[A-Za-z0-9_]{36}$/.test(t)?{isValid:!0,confidenceBonus:10,reason:"GitHub Server-to-server token"}:/^github_pat_[A-Za-z0-9_]{82}$/.test(t)?{isValid:!0,confidenceBonus:15,reason:"GitHub Fine-Grained Personal Access Token"}:{isValid:!1,confidenceBonus:0,reason:"Invalid GitHub token prefix or length"}}function He(t){let e=t.split(".");if(e.length!==3)return{isValid:!1,confidenceBonus:0,reason:"Not a 3-part dot-separated JWT"};try{let i=Buffer.from(e[0],"base64url").toString("utf8"),n=JSON.parse(i);if(n&&typeof n=="object"&&n.alg)return{isValid:!0,confidenceBonus:15,reason:`Valid JWT structure with signature algorithm: ${n.alg}`}}catch{}return{isValid:!1,confidenceBonus:0,reason:"Malformed JWT header JSON payload"}}function Ge(t){try{let e=new URL(t);if(!["postgres:","postgresql:","mysql:","mongodb:","mongodb+srv:","redis:"].includes(e.protocol))return{isValid:!1,confidenceBonus:0,reason:"Unsupported database protocol scheme"};if(e.password&&e.password.length>0)return{isValid:!0,confidenceBonus:12,reason:`Database connection string containing credentials for user '${e.username||"default"}'`}}catch{let e=/^(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis):\/\/[^:\s'"]+:([^\s'"]+)@([a-zA-Z0-9_.-]+(?::[0-9]+)?\/[^\s'"`;]*)/i,i=t.match(e);if(i&&i[1])return{isValid:!0,confidenceBonus:10,reason:"Database connection URI structure matched with embedded password"}}return{isValid:!1,confidenceBonus:0,reason:"Invalid database connection URL structure"}}function Ve(t){return/^sk-proj-[A-Za-z0-9_-]{48,}$/.test(t)?{isValid:!0,confidenceBonus:15,reason:"Valid OpenAI Project API Key format"}:/^sk-admin-[A-Za-z0-9_-]{48,}$/.test(t)?{isValid:!0,confidenceBonus:15,reason:"Valid OpenAI Admin/Organization API Key format"}:/^sk-svcacct-[A-Za-z0-9_-]{48,}$/.test(t)?{isValid:!0,confidenceBonus:15,reason:"Valid OpenAI Service Account Key format"}:/^sk-[A-Za-z0-9]{32,48}$/.test(t)?{isValid:!0,confidenceBonus:10,reason:"Valid OpenAI Standard/Legacy API Key format"}:{isValid:!1,confidenceBonus:0,reason:"Invalid OpenAI API key structure"}}function Ue(t){return/^sk-ant-[A-Za-z0-9_-]{40,}$/.test(t)?{isValid:!0,confidenceBonus:15,reason:"Valid Anthropic Claude API Key format"}:{isValid:!1,confidenceBonus:0,reason:"Invalid Anthropic API key format"}}function je(t){return/^AIza[0-9A-Za-z_-]{35}$/.test(t)?{isValid:!0,confidenceBonus:12,reason:"Valid Google Cloud / Gemini AIza service key signature"}:{isValid:!1,confidenceBonus:0,reason:"Invalid Google Cloud API key format"}}function Ze(t){return/^xox[baprs]-[0-9A-Za-z-]{10,72}$/.test(t)?{isValid:!0,confidenceBonus:12,reason:`Valid Slack ${t.startsWith("xoxb")?"Bot Token":t.startsWith("xoxp")?"User Token":"OAuth Token"} signature`}:{isValid:!1,confidenceBonus:0,reason:"Invalid Slack token structure"}}function Ye(t){return/^hf_[A-Za-z0-9]{34}$/.test(t)?{isValid:!0,confidenceBonus:12,reason:"Valid Hugging Face User Access Token format"}:{isValid:!1,confidenceBonus:0,reason:"Invalid Hugging Face token structure"}}function qe(t){return/^[A-Za-z0-9/+=]{40}$/.test(t)?{isValid:!0,confidenceBonus:12,reason:"Valid 40-character AWS Secret Access Key Base64 format"}:{isValid:!1,confidenceBonus:0,reason:"Invalid AWS Secret Access Key format"}}function Je(t){return/^https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9_]{8,12}\/B[A-Z0-9_]{8,12}\/[A-Za-z0-9_]{24}$/.test(t)?{isValid:!0,confidenceBonus:15,reason:"Valid Slack Incoming Webhook URL structure"}:{isValid:!1,confidenceBonus:0,reason:"Invalid Slack Incoming Webhook URL"}}function Xe(t){return/^[A-Za-z0-9/+=]{86,88}==$/.test(t)?{isValid:!0,confidenceBonus:12,reason:"Valid Azure Storage Account Key Base64 format with padding"}:{isValid:!1,confidenceBonus:0,reason:"Invalid Azure Storage Key format"}}function Qe(t){let e=/-----BEGIN (?:[A-Z0-9_-]+ )*PRIVATE KEY(?: BLOCK)?-----/.test(t),i=/-----END (?:[A-Z0-9_-]+ )*PRIVATE KEY(?: BLOCK)?-----/.test(t);return e&&i?{isValid:!0,confidenceBonus:20,reason:"Valid Cryptographic Private Key PEM block container"}:{isValid:!1,confidenceBonus:0,reason:"Incomplete or malformed PEM key container"}}function Ce(t,e,i,n,s,o){let r=[],c=t.baseConfidence;r.push({signal:"KNOWN_PATTERN_MATCH",description:`Matched recognized credential signature for ${t.provider} (${t.name})`,confidenceImpact:0,details:{ruleId:t.id,provider:t.provider}});let d=se(e),l=Me(e),{setName:u}=xe(e);if(t.minEntropy&&d<t.minEntropy?(c=Math.max(10,c-30),r.push({signal:"LOW_ENTROPY",description:`Low entropy score: ${d} bits/char below minimum threshold of ${t.minEntropy}`,confidenceImpact:-30,details:{shannonEntropy:d,minEntropy:t.minEntropy}})):d>=4.5?(c=Math.min(100,c+5),r.push({signal:"HIGH_ENTROPY",description:`Cryptographic entropy: ${d} bits/char (${u} set), indicates non-human randomness`,confidenceImpact:5,details:{shannonEntropy:d,normalizedEntropy:l,characterSet:u}})):d>=3.4?r.push({signal:"MODERATE_ENTROPY",description:`Moderate entropy: ${d} bits/char (${u} set)`,confidenceImpact:0,details:{shannonEntropy:d,normalizedEntropy:l,characterSet:u}}):(c=Math.max(10,c-15),r.push({signal:"LOW_ENTROPY",description:`Low entropy score: ${d} bits/char (${u} set)`,confidenceImpact:-15,details:{shannonEntropy:d,normalizedEntropy:l,characterSet:u}})),n.isSensitiveIdentifier||o?.isSensitiveProperty){let h=o?.variablePath||n.inferredVariable||"credential";c=Math.min(100,c+10),r.push({signal:"SENSITIVE_IDENTIFIER",description:`Assigned to sensitive identifier / property: '${h}'`,confidenceImpact:10,details:{identifier:h}})}else n.isBenignIdentifier&&(c=Math.max(10,c-25),r.push({signal:"BENIGN_IDENTIFIER",description:`Identifier name indicates mock or sample value: '${n.inferredVariable}'`,confidenceImpact:-25,details:{identifier:n.inferredVariable}}));o?.isEnvFallback&&(c=Math.min(100,c+12),r.push({signal:"ENV_FALLBACK_ASSIGNMENT",description:'Hardcoded literal provided as environment variable fallback (e.g. process.env.KEY || "...")',confidenceImpact:12})),o?.isAuthorizationHeader&&(c=Math.min(100,c+10),r.push({signal:"AUTHORIZATION_HEADER",description:"Passed in HTTP Authorization or Bearer token header context",confidenceImpact:10})),(i.isConfig||i.isSensitiveName)&&(c=Math.min(100,c+8),r.push({signal:"PRODUCTION_CONFIG_FILE",description:`Located in configuration or secret storage file (${i.fileExtension})`,confidenceImpact:8,details:{isConfig:i.isConfig,extension:i.fileExtension}})),i.isTest&&(c=Math.max(20,c-20),r.push({signal:"TEST_FILE_PENALTY",description:"Found inside test/mock directory structure",confidenceImpact:-20})),i.isDoc&&(c=Math.max(20,c-25),r.push({signal:"DOCUMENTATION_PENALTY",description:"Found inside documentation or markdown guide",confidenceImpact:-25}));let a;t.id==="aws-access-key"?a=Ke(e):t.id==="aws-secret-key"?a=qe(e):t.id==="stripe-secret-key"?a=We(e):t.id==="github-pat"?a=ze(e):t.id==="jwt-token"?a=He(e):t.id==="database-url"?a=Ge(e):t.id==="openai-api-key"?a=Ve(e):t.id==="anthropic-api-key"?a=Ue(e):t.id==="google-api-key"?a=je(e):t.id==="slack-bot-token"?a=Ze(e):t.id==="slack-webhook"?a=Je(e):t.id==="azure-storage-key"?a=Xe(e):t.id==="huggingface-token"?a=Ye(e):t.id==="private-key"&&(a=Qe(e)),a&&a.isValid&&(c=Math.min(100,c+a.confidenceBonus),r.push({signal:"STRUCTURAL_VALIDATION_PASSED",description:`Structural validation verified: ${a.reason}`,confidenceImpact:a.confidenceBonus}));let p=Be(e,n.inferredVariable,s);if(p.isFalsePositive)return{confidence:0,evidence:{items:[{signal:"KNOWN_PLACEHOLDER_REJECTED",description:p.reason||"Placeholder value rejected",confidenceImpact:-100}],shannonEntropy:d,normalizedEntropy:l,characterSet:u,surroundingCode:{before:n.surroundingBefore,targetLine:n.matchedLine,after:n.surroundingAfter,inferredVariable:n.inferredVariable},fileContext:{fileExtension:i.fileExtension,isConfig:i.isConfig,isTest:i.isTest,isDoc:i.isDoc,isSensitiveName:i.isSensitiveName,isExampleOrSample:i.isExampleOrSample}},isSuppressed:!0,suppressReason:p.reason};p.confidencePenalty>0&&(c=Math.max(10,c-p.confidencePenalty));let g=Math.max(0,Math.min(100,Math.round(c))),f={items:r,shannonEntropy:d,normalizedEntropy:l,characterSet:u,surroundingCode:{before:n.surroundingBefore,targetLine:n.matchedLine,after:n.surroundingAfter,inferredVariable:n.inferredVariable},fileContext:{fileExtension:i.fileExtension,isConfig:i.isConfig,isTest:i.isTest,isDoc:i.isDoc,isSensitiveName:i.isSensitiveName,isExampleOrSample:i.isExampleOrSample}};return{confidence:g,evidence:f,isSuppressed:!1}}function Ie(t,e,i,n){let s=[],o=0,r=Math.min(40,Math.round(t.baseRiskWeight/100*40));o+=r,s.push({factor:"CREDENTIAL_SEVERITY",weight:40,scoreContribution:r,explanation:`${t.provider} ${t.name} has high inherent privilege capability`});let c=Math.round(e/100*25);o+=c,s.push({factor:"CONFIDENCE_LEVEL",weight:25,scoreContribution:c,explanation:`Multi-signal verification confidence is ${e}%`});let d=5,l="Standard source code file";i.isConfig||i.isSensitiveName?(d=15,l="Located in sensitive deployment / environment configuration"):i.isTest?(d=0,l="Located in test / fixture codebase with reduced operational blast radius"):i.isDoc&&(d=0,l="Located in documentation context"),o+=d,s.push({factor:"STORAGE_ENVIRONMENT",weight:15,scoreContribution:d,explanation:l});let u=5,a="Found in local uncommitted working tree";n&&(n.isRemote?(u=20,a="Pushed to remote repository branch (external exposure risk)"):n.isPresentInHistory?(u=16,a=`Committed to Git history across ${n.branches.length||1} branch(es) (${n.exposureDurationDays} days exposure)`):n.isPresentInHead&&(u=12,a="Committed in current HEAD commit")),o+=u,s.push({factor:"EXPOSURE_REACH",weight:20,scoreContribution:u,explanation:a});let p=Math.max(0,Math.min(100,Math.round(o))),g="LOW";p>=76?g="CRITICAL":p>=51?g="HIGH":p>=26?g="MEDIUM":g="LOW";let f=Nt(p,n),h=`${g} Risk (${p}/100) \u2014 ${t.name}. ${f.summary}`;return{score:p,tier:g,factors:s,blastRadius:f,summary:h}}function Nt(t,e){let i=[],n=Math.round(t*.5),s=e?e.isPresentInHead:!0,o=e?e.isPresentInHistory:!1,r=e?.isPresentInHistory?1:0,c=e?.branches||["main"],d=c.length,l=e?.isRemote||!1,u=e?.exposureDurationDays||0;s&&(i.push("Active working tree contains exposed secret"),n+=15),o&&(i.push(`Git history contains commit records across ${d} branch(es)`),n+=20),l&&(i.push("Secret has been synchronized to remote tracking branches"),n+=25),u>7&&(i.push(`Exposure duration exceeds ${u} days without rotation`),n+=10),n=Math.max(0,Math.min(100,n));let a="CONTAINED";n>=75?a="SEVERE":n>=50?a="EXTENSIVE":n>=25?a="MODERATE":a="CONTAINED";let p=`Blast Radius: ${a} (${n}/100) \u2014 ${l?"Remote & history exposure":o?"Historical commit exposure":"Contained to local working tree"}`;return{level:a,score:n,workingTreeExposed:s,gitHistoryExposed:o,commitCount:r,branchCount:d,branches:c,remoteExposed:l,exposureDurationDays:u,summary:p,factors:i}}var j=I(require("fs")),me=I(require("path"));var et=I(require("crypto")),Mt="sld_fingerprint_salt_v1_d8e9f2a1b4c3e7f0";function oe(t){if(!t)return"";let e=t.length;if(e<=12)return"\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022";let i=Math.max(2,Math.floor(e*.2)),n=Math.min(4,Math.max(1,Math.floor(i/2))),s=Math.min(3,Math.max(1,i-n)),o=Math.max(6,Math.min(16,e-n-s)),r=t.substring(0,n),c=t.substring(e-s),d="\u2022".repeat(o);return`${r}${d}${c}`}function we(t){return et.createHmac("sha256",Mt).update(t).digest("hex").substring(0,16)}function fe(t){return t.replace(/\\/g,"\\\\").replace(/"/g,'\\"').replace(/\$/g,"\\$").replace(/\n/g,"\\n").replace(/\r/g,"\\r")}function Re(t,e){switch(me.extname(t).toLowerCase()){case".py":return`os.environ.get("${e}")`;case".go":return`os.Getenv("${e}")`;case".rb":return`ENV['${e}']`;case".php":return`getenv('${e}')`;case".java":case".kt":return`System.getenv("${e}")`;case".rs":return`std::env::var("${e}").unwrap()`;case".sh":case".bash":case".zsh":return`"\${${e}}"`;case".yaml":case".yml":case".toml":case".env":return`\${${e}}`;case".js":case".jsx":case".ts":case".tsx":case".mjs":case".cjs":default:return`process.env.${e}`}}function _e(t,e,i,n,s){let o=t.suggestedEnvName(s),r=Re(i,o),c=oe(e),d=fe(e),l=[`1. Revoke / rotate credential immediately with provider: ${t.provider}`,`2. Migrate secret value to local .env file (${o})`,`3. Replace hardcoded literal in ${i} with ${r}`,"4. Verify .env is listed in .gitignore so it is never committed","5. If committed previously, purge from Git history using git-filter-repo or BFG","6. Rescan file and commit to verify exposure is eliminated"],u=`${o}="${d}"`,a=`${o}=your_${o.toLowerCase()}_here`,p=`# WARNING: Use BFG Repo Cleaner to purge secrets from history (safer than filter-repo --invert-paths):
#   java -jar bfg.jar --replace-text secrets.txt <repo-dir>
# Where secrets.txt lists the exact literal to redact (one per line).
# Then force-push: git push --force --all && git push --force --tags
# Alternatively with git-filter-repo (rewrites content, not paths):
#   git filter-repo --replace-text secrets.txt`,g=`--- a/${i}
+++ b/${i}
@@ -${n},1 +${n},1 @@
- ... "${c}" ...
+ ... ${r} ...`;return{steps:l,envVarName:o,replacementCode:r,envFileSnippet:u,envExampleSnippet:a,gitHistoryPurgeCommand:p,diffPreview:g}}function tt(t,e,i){let n=t.split(/\r?\n/),s=new Map;for(let o of n){let r=o.trim();if(!r||r.startsWith("#"))continue;let c=r.indexOf("=");if(c!==-1){let d=r.substring(0,c).trim(),l=r.substring(c+1).trim();(l.startsWith('"')&&l.endsWith('"')||l.startsWith("'")&&l.endsWith("'"))&&(l=l.substring(1,l.length-1)),s.set(d,l)}}if(s.has(e)){let o=s.get(e);if(o===fe(i)||o===i)return{varName:e,isReused:!0};let r=2;for(;s.has(`${e}_${r}`);){if(s.get(`${e}_${r}`)===i)return{varName:`${e}_${r}`,isReused:!0};r++}return{varName:`${e}_${r}`,isReused:!1}}return{varName:e,isReused:!1}}function nt(t){let e=me.join(t,".gitignore");if(j.existsSync(e)){let i=j.readFileSync(e,"utf8");if(!i.split(/\r?\n/).some(o=>/^\s*\.env(?:\s|$)/.test(o))){let o=i.endsWith(`
`)||i.length===0?"":`
`;j.appendFileSync(e,`${o}# Credentials
.env
.env.*.local
`,"utf8")}}else j.writeFileSync(e,`# Credentials
.env
.env.*.local
`,"utf8");try{let{execFileSync:i}=require("child_process");try{i("git",["rev-parse","--is-inside-work-tree"],{cwd:t,stdio:"ignore"})}catch{return}try{throw i("git",["ls-files","--error-unmatch",".env"],{cwd:t,stdio:"ignore"}),new Error('.env is already tracked in Git index. Run "git rm --cached .env" to untrack it before storing secrets.')}catch(n){if(n.message&&n.message.includes("already tracked in Git index"))throw n}try{i("git",["check-ignore","-q",".env"],{cwd:t,stdio:"ignore"})}catch{throw new Error(".env is not ignored by Git according to git check-ignore.")}}catch(i){if(i.message&&(i.message.includes("already tracked")||i.message.includes("not ignored by Git")))throw i}}function it(t){return st.createHash("sha256").update(t.replace(/\\/g,"/")).digest("hex").slice(0,8)}function Bt(t,e=4e3){if(t.length<e)return t;let i=!1,n=-1;for(let r=0;r<t.length;r++)if(t.charCodeAt(r)===10){if(r-n>e){i=!0;break}n=r}if(!i&&t.length-n<=e)return t;let s=t.split(/\r?\n/),o=[];for(let r of s)if(r.length<=e)o.push(r);else for(let c=0;c<r.length;c+=e-100)o.push(r.substring(c,c+e));return o.join(`
`)}function re(t,e,i={}){let n=typeof i=="string"?{workspaceRoot:i}:i,s=Bt(t),o=n.rules||Le,r=n.workspaceRoot,c=Oe(e,r),d=[],l=null;function u(){if(!l){l=[0];for(let v=0;v<s.length;v++)s.charCodeAt(v)===10&&l.push(v+1)}return l}function a(v){let k=u(),T=0,D=k.length-1;for(;T<=D;){let P=T+D>>1;if(k[P]<=v){if(P===k.length-1||k[P+1]>v)return{line:P+1,column:v-k[P]+1};T=P+1}else D=P-1}return{line:1,column:v+1}}let p=null;function g(v){if(s.length<=1024*1024)return p||(p=s.split(/\r?\n/)),{lines:p,relativeTargetIdx:v-1};let k=u(),T=v-1,D=Math.max(0,T-30),P=Math.min(k.length-1,T+30),H=k[D],G=P+1<k.length?k[P+1]:s.length;return{lines:s.substring(H,G).split(/\r?\n/),relativeTargetIdx:T-D}}for(let v of o){v.pattern.lastIndex=0;let k;for(;(k=v.pattern.exec(s))!==null;){let T=k[1]!==void 0?k[1]:k[0],D=k[1]!==void 0?k[0].indexOf(k[1]):0,P=k.index+(D>=0?D:0),{line:H,column:G}=a(P),V=g(H),te=Se(V.lines,V.relativeTargetIdx),B=Ee(V.lines,V.relativeTargetIdx,e),O=Ce(v,T,c,te,e,B);if(O.isSuppressed)continue;let U;if(v.minEntropy!==void 0&&(U=n.minEntropyThreshold!==void 0?Math.max(v.minEntropy,n.minEntropyThreshold):v.minEntropy),U!==void 0&&O.evidence.shannonEntropy<U)continue;let Z=e;if(r){let ie=X.relative(r,e);!ie.startsWith("..")&&!X.isAbsolute(ie)&&(Z=ie)}let ne=Ie(v,O.confidence,c),ce=_e(v,T,Z,H,te.inferredVariable),de=it(Z),le=we(T),Ae=`sec_${le}_${de}_${H}`,Y=oe(T),At={id:Ae,fingerprint:le,type:v.name,provider:v.provider,file:Z,fullPath:e,line:H,column:G,length:T.length,rawSecret:T,redactedSecret:Y,confidence:O.confidence,risk:ne.tier,riskAssessment:ne,evidence:O.evidence,remediation:ce,status:"ACTIVE",detectedAt:new Date().toISOString(),signals:O.evidence.items.map(ie=>ie.description),exampleFix:ce.replacementCode,entropy:O.evidence.shannonEntropy};d.push(At)}}let f=[],h=/["']([^"'\r\n]{2,80})["']\s*\+\s*["']([^"'\r\n]{8,120})["']/g,S;for(;(S=h.exec(s))!==null;)f.push({combined:S[1]+S[2],matchOffset:S.index,matchLength:S[0].length,description:"Resolved split string concatenation"});let R=/\[\s*["']([^"'\r\n]{2,80})["']\s*,\s*["']([^"'\r\n]{8,120})["'](?:\s*,\s*["']([^"'\r\n]{2,120})["'])*\s*\]\s*\.\s*join\s*\(\s*["']\s*["']\s*\)/g,x;for(;(x=R.exec(s))!==null;){let v=[x[1],x[2],x[3]].filter(Boolean);f.push({combined:v.join(""),matchOffset:x.index,matchLength:x[0].length,description:"Resolved split array join expression"})}let M=/`([^`\r\n]{2,80})\$\{\s*["']([^"'\r\n]{8,120})["']\s*\}([^`\r\n]*?)`/g,y;for(;(y=M.exec(s))!==null;)f.push({combined:y[1]+y[2]+(y[3]||""),matchOffset:y.index,matchLength:y[0].length,description:"Resolved template literal interpolation"});let $=/(?:Buffer\.from|atob|b64decode)\s*\(\s*(?:b)?["']([A-Za-z0-9+/=]{24,200})["']/g,C;for(;(C=$.exec(s))!==null;)try{let v=Buffer.from(C[1],"base64").toString("utf8");v.length>=10&&/^[\x20-\x7E\r\n]+$/.test(v)&&f.push({combined:v,matchOffset:C.index,matchLength:C[0].length,description:"Resolved base64-encoded credential payload"})}catch{}for(let v of f)for(let k of o){k.pattern.lastIndex=0;let T;for(;(T=k.pattern.exec(v.combined))!==null;){let D=T[1]||T[0],{line:P,column:H}=a(v.matchOffset),G=g(P),V=Se(G.lines,G.relativeTargetIdx),te=Ee(G.lines,G.relativeTargetIdx,e),B=Ce(k,D,c,V,e,te);if(B.isSuppressed)continue;let O;if(k.minEntropy!==void 0&&(O=n.minEntropyThreshold!==void 0?Math.max(k.minEntropy,n.minEntropyThreshold):k.minEntropy),O!==void 0&&B.evidence.shannonEntropy<O)continue;let U=e;if(r){let Y=X.relative(r,e);!Y.startsWith("..")&&!X.isAbsolute(Y)&&(U=Y)}let Z=Ie(k,B.confidence,c),ne=_e(k,D,U,P,V.inferredVariable);B.evidence.items.unshift({signal:"ADVERSARIAL_DEOBFUSCATION_RESOLVED",description:v.description,confidenceImpact:10});let ce=it(U),de=we(D),le=`sec_${de}_${ce}_${P}`,Ae=oe(D);d.push({id:le,fingerprint:de,type:k.name,provider:k.provider,file:U,fullPath:e,line:P,column:H,length:v.matchLength,rawSecret:D,redactedSecret:Ae,confidence:Math.min(100,B.confidence+5),risk:Z.tier,riskAssessment:Z,evidence:B.evidence,remediation:ne,status:"ACTIVE",detectedAt:new Date().toISOString(),signals:B.evidence.items.map(Y=>Y.description),exampleFix:ne.replacementCode,entropy:B.evidence.shannonEntropy})}}return Kt(d)}function Kt(t){let e=[];for(let i of t){let n=e.findIndex(s=>s.file===i.file&&s.line===i.line&&(s.rawSecret.includes(i.rawSecret)||i.rawSecret.includes(s.rawSecret)));if(n===-1)e.push(i);else{let s=e[n];(s.provider==="Generic Credential"&&i.provider!=="Generic Credential"||i.confidence>s.confidence)&&(e[n]=i)}}return e}var he=class{diagnosticCollection;currentFindings=new Map;ignoredFindings=new Set;onFindingsChangedEmitter=new _.EventEmitter;onFindingsChanged=this.onFindingsChangedEmitter.event;minEntropy;constructor(){this.diagnosticCollection=_.languages.createDiagnosticCollection("secret-leak-detector")}setMinEntropy(e){this.minEntropy=e}getDiagnosticCollection(){return this.diagnosticCollection}getAllFindings(){let e=[];for(let i of this.currentFindings.values())e.push(...i);return e}clear(){this.diagnosticCollection.clear(),this.currentFindings.clear(),this.onFindingsChangedEmitter.fire([])}ignoreFinding(e){this.ignoredFindings.add(e);for(let[i,n]of this.currentFindings.entries()){let s=n.filter(o=>o.id!==e);if(s.length!==n.length){this.currentFindings.set(i,s);let o=_.Uri.file(i),r=this.diagnosticCollection.get(o);if(r){let c=r.filter(d=>(typeof d.code=="object"?d.code?.value:d.code)!==e);this.diagnosticCollection.set(o,c)}}}this.onFindingsChangedEmitter.fire(this.getAllFindings())}setIgnoredFindings(e){this.ignoredFindings=new Set(e)}getIgnoredFindings(){return Array.from(this.ignoredFindings)}scanDocument(e){if(e.uri.scheme!=="file")return[];let i=e.getText();if(i.length>2*1024*1024)return[];let n=_.workspace.getWorkspaceFolder(e.uri),o={workspaceRoot:n?n.uri.fsPath:void 0,minEntropyThreshold:this.minEntropy},c=re(i,e.uri.fsPath,o).filter(l=>!this.ignoredFindings.has(l.id));this.currentFindings.set(e.uri.fsPath,c);let d=[];for(let l of c){let u=Math.max(0,l.line-1),a=Math.max(0,l.column-1),p=new _.Position(u,a),g=e.offsetAt(p),f=e.positionAt(g+l.length),h=new _.Range(p,f),S=_.DiagnosticSeverity.Warning;l.risk==="CRITICAL"||l.risk==="HIGH"?S=_.DiagnosticSeverity.Error:l.risk==="LOW"&&(S=_.DiagnosticSeverity.Information);let R=typeof l.remediation=="string"?l.remediation:l.remediation?.steps?.[0]||"Migrate to .env",x=new _.Diagnostic(h,`[Secret Leak Detector] ${l.type} detected! Confidence: ${l.confidence}%. ${R}`,S);x.code={value:l.id,target:_.Uri.parse("https://github.com/MokuLakshithReddy/Secret_Leak_Detector")},x.source="Secret Leak Detector",d.push(x)}return this.diagnosticCollection.set(e.uri,d),this.onFindingsChangedEmitter.fire(this.getAllFindings()),c}removeDocument(e){this.diagnosticCollection.delete(e),this.currentFindings.delete(e.fsPath),this.onFindingsChangedEmitter.fire(this.getAllFindings())}dispose(){this.diagnosticCollection.dispose(),this.onFindingsChangedEmitter.dispose()}};var E=I(require("vscode")),L=I(require("fs")),Te=I(require("path"));var Q=class{static providedCodeActionKinds=[E.CodeActionKind.QuickFix];diagnosticProvider;constructor(e){this.diagnosticProvider=e}provideCodeActions(e,i,n){let s=[],o=n.diagnostics.filter(c=>c.source==="Secret Leak Detector");if(o.length===0)return s;let r=this.diagnosticProvider.getAllFindings();for(let c of o){let d=typeof c.code=="object"?c.code?.value:c.code,l=r.find(g=>g.id===d);if(!l||e.getText(c.range)!==l.rawSecret)continue;let a=this.createMoveToEnvAction(e,c.range,l);s.push(a);let p=new E.CodeAction("Ignore this finding (False Positive)",E.CodeActionKind.QuickFix);p.command={command:"secret-leak-detector.ignoreFinding",title:"Ignore Finding",arguments:[l.id]},s.push(p)}return s}createMoveToEnvAction(e,i,n){let s=new E.CodeAction(`\u{1F6E1}\uFE0F Move ${n.type} to .env and replace with environment variable`,E.CodeActionKind.QuickFix);return s.isPreferred=!0,s.command={command:"secret-leak-detector.remediateFinding",title:"Move to .env",arguments:[e.uri,i,n]},s}static async executeRemediation(e,i,n){let s=E.workspace.getWorkspaceFolder(e);if(!s){E.window.showErrorMessage("No workspace folder found to save .env file.");return}let o=await E.workspace.openTextDocument(e);if(o.getText(i)!==n.rawSecret){E.window.showErrorMessage("The secret at the target location has changed or was already removed.");return}let r=s.uri.fsPath,c=Te.join(r,".env"),d=n.remediation?.envVarName;d||(n.type.includes("AWS Access Key")?d="AWS_ACCESS_KEY_ID":n.type.includes("AWS Secret")?d="AWS_SECRET_ACCESS_KEY":n.type.includes("GitHub")?d="GITHUB_TOKEN":n.type.includes("OpenAI")?d="OPENAI_API_KEY":n.type.includes("Anthropic")?d="ANTHROPIC_API_KEY":n.type.includes("Stripe")?d="STRIPE_SECRET_KEY":n.type.includes("Slack")?d="SLACK_TOKEN":n.type.includes("Database")?d="DATABASE_URL":d=`${n.provider.replace(/[^a-zA-Z0-9]/g,"_").toUpperCase()}_API_KEY`);let l="",u=!1;if(L.existsSync(c)){u=!0;try{l=L.readFileSync(c,"utf8")}catch(y){E.window.showErrorMessage(`Failed to read .env file: ${y}`);return}}let{varName:a,isReused:p}=tt(l,d,n.rawSecret);try{nt(r)}catch(y){E.window.showErrorMessage(`Failed to verify .gitignore security: ${y.message||y}`);return}let g=i,f=!1;if(i.start.character>0){let y=i.start.translate(0,-1),$=i.end.translate(0,1),C=o.getText(new E.Range(y,i.start)),v=o.getText(new E.Range(i.end,$));(C==='"'&&v==='"'||C==="'"&&v==="'")&&(g=new E.Range(y,$),f=!0)}let h=Re(e.fsPath,a),S=new E.WorkspaceEdit;if(S.replace(e,g,h),!await E.workspace.applyEdit(S)){E.window.showErrorMessage("Failed to modify source document. Remediation aborted with zero file alterations.");return}let x=fe(n.rawSecret),M=`${a}="${x}"
`;try{if(!p)if(!u)L.writeFileSync(c,M,{mode:384,encoding:"utf8"});else{let C=l.endsWith(`
`)||l.length===0?"":`
`;L.appendFileSync(c,`${C}${M}`,{mode:384,encoding:"utf8"})}let y=Te.join(r,".env.example"),$=`${a}=your_${a.toLowerCase()}_here
`;if(!L.existsSync(y)||!L.readFileSync(y,"utf8").includes(a)){let C=L.existsSync(y)?L.readFileSync(y,"utf8"):"",v=C.endsWith(`
`)||C.length===0?"":`
`;L.appendFileSync(y,`${v}${$}`,"utf8")}}catch(y){let $=new E.Range(g.start,g.start.translate(0,h.length)),C=new E.WorkspaceEdit;C.replace(e,$,f?`"${n.rawSecret}"`:n.rawSecret),await E.workspace.applyEdit(C),E.window.showErrorMessage(`Failed to write to .env: ${y}. Document edit was safely rolled back.`);return}E.window.showInformationMessage(`\u2705 Moved ${n.type} to .env (${a}) and verified .gitignore protection!`)}};var b=I(require("vscode")),ve=class{_onDidChangeTreeData=new b.EventEmitter;onDidChangeTreeData=this._onDidChangeTreeData.event;findings=[];updateFindings(e){this.findings=e,this._onDidChangeTreeData.fire()}getTreeItem(e){return e}getChildren(e){if(!e){if(this.findings.length===0){let s=new W("No Leaks Detected (Safe)",b.TreeItemCollapsibleState.None);return s.iconPath=new b.ThemeIcon("shield-check",new b.ThemeColor("testing.iconPassed")),s.description="Workspace is clean",Promise.resolve([s])}let i=["CRITICAL","HIGH","MEDIUM","LOW"],n=[];for(let s of i){let o=this.findings.filter(r=>r.risk===s).length;if(o>0){let r=new W(`${s} Risk (${o})`,b.TreeItemCollapsibleState.Expanded,s);s==="CRITICAL"?r.iconPath=new b.ThemeIcon("error",new b.ThemeColor("errorForeground")):s==="HIGH"?r.iconPath=new b.ThemeIcon("warning",new b.ThemeColor("editorWarning.foreground")):s==="MEDIUM"?r.iconPath=new b.ThemeIcon("info",new b.ThemeColor("editorInfo.foreground")):r.iconPath=new b.ThemeIcon("pass",new b.ThemeColor("testing.iconPassed")),n.push(r)}}return Promise.resolve(n)}if(e.contextValue){let i=e.contextValue,s=this.findings.filter(o=>o.risk===i).map(o=>{let r=new W(`${o.type}`,b.TreeItemCollapsibleState.None);return r.description=`${o.file}:${o.line}`,r.tooltip=new b.MarkdownString(`**${o.type}** (${o.provider})

- **Risk:** ${o.risk}
- **Confidence:** ${o.confidence}%
- **Entropy:** ${o.entropy} bits/char
- **Secret:** \`${o.redactedSecret}\`

*Suggested Fix: ${o.remediation?.replacementCode||o.remediation?.envVarName||"Migrate to .env"}*`),r.iconPath=new b.ThemeIcon("key"),r.command={command:"vscode.open",title:"Jump to Secret",arguments:[b.Uri.file(o.fullPath),{selection:new b.Range(o.line-1,o.column-1,o.line-1,o.column-1+o.length)}]},r});return Promise.resolve(s)}return Promise.resolve([])}},be=class{_onDidChangeTreeData=new b.EventEmitter;onDidChangeTreeData=this._onDidChangeTreeData.event;findingsCount=0;isGit=!0;update(e,i){this.findingsCount=e,this.isGit=i,this._onDidChangeTreeData.fire()}getTreeItem(e){return e}getChildren(){let e=[],i=new W(this.findingsCount===0?"Status: Protected":`Status: ${this.findingsCount} Leaks Active`,b.TreeItemCollapsibleState.None);i.iconPath=new b.ThemeIcon(this.findingsCount===0?"check":"alert",this.findingsCount===0?new b.ThemeColor("testing.iconPassed"):new b.ThemeColor("errorForeground")),e.push(i);let n=new W("Run Full Workspace Scan",b.TreeItemCollapsibleState.None);n.iconPath=new b.ThemeIcon("search"),n.command={command:"secret-leak-detector.scanWorkspace",title:"Scan Workspace"},e.push(n);let s=new W("Check Git Staged Changes",b.TreeItemCollapsibleState.None);s.iconPath=new b.ThemeIcon("git-commit"),s.command={command:"secret-leak-detector.scanStaged",title:"Scan Staged Changes"},e.push(s);let o=new W("Open Interactive Dashboard",b.TreeItemCollapsibleState.None);o.iconPath=new b.ThemeIcon("dashboard"),o.command={command:"secret-leak-detector.openDashboard",title:"Open Dashboard"},e.push(o);let r=new W("Install Pre-Commit Hook",b.TreeItemCollapsibleState.None);return r.iconPath=new b.ThemeIcon("terminal"),r.command={command:"secret-leak-detector.installGitHook",title:"Install Hook"},e.push(r),Promise.resolve(e)}},W=class extends b.TreeItem{constructor(e,i,n){super(e,i),this.contextValue=n}};var F=I(require("vscode")),ot=I(require("crypto")),rt=I(require("fs")),at=I(require("path"));function Pe(t){let e=typeof t.remediation=="string"?t.remediation:t.remediation?.steps?.join("; ")||"Rotate and move to .env",i=t.exampleFix||t.remediation?.replacementCode||"";return{id:t.id,type:t.type,provider:t.provider,file:t.file,fullPath:t.fullPath,line:t.line,column:t.column,redactedSecret:t.redactedSecret,confidence:t.confidence,entropy:t.entropy??0,risk:t.risk,remediationText:e,exampleFix:i}}var q=class t{static currentPanel;static viewType="secretLeakDetectorDashboard";_panel;_extensionUri;_disposables=[];_findings=[];static createOrShow(e,i){let n=F.window.activeTextEditor?F.window.activeTextEditor.viewColumn:void 0;if(t.currentPanel){t.currentPanel._panel.reveal(n),t.currentPanel.updateFindings(i);return}let s=F.window.createWebviewPanel(t.viewType,"\u{1F510} Secret Leak Detector Dashboard",n||F.ViewColumn.One,{enableScripts:!0,retainContextWhenHidden:!0,localResourceRoots:[e]});t.currentPanel=new t(s,e,i)}constructor(e,i,n){this._panel=e,this._extensionUri=i,this._findings=n,this._update(),this._panel.onDidDispose(()=>this.dispose(),null,this._disposables),this._panel.webview.onDidReceiveMessage(async s=>{switch(s.command){case"scanWorkspace":F.commands.executeCommand("secret-leak-detector.scanWorkspace");return;case"scanStaged":F.commands.executeCommand("secret-leak-detector.scanStaged");return;case"installHook":F.commands.executeCommand("secret-leak-detector.installGitHook");return;case"openFile":if(typeof s.file=="string"&&s.file.trim().length>0&&typeof s.line=="number"&&s.line>=1){let o=at.resolve(s.file);if(rt.existsSync(o))try{let r=await F.workspace.openTextDocument(F.Uri.file(o));await F.window.showTextDocument(r,{selection:new F.Range(s.line-1,0,s.line-1,0)})}catch{}}return}},null,this._disposables)}updateFindings(e){this._findings=e;let i=this._findings.map(Pe);this._panel.webview.postMessage({command:"updateData",findings:i})}dispose(){for(t.currentPanel=void 0,this._panel.dispose();this._disposables.length;){let e=this._disposables.pop();e&&e.dispose()}}_update(){this._panel.webview.html=this._getHtmlForWebview()}_getHtmlForWebview(){let e=ot.randomBytes(16).toString("base64"),i=this._findings.map(Pe),n=JSON.stringify(i).replace(/</g,"\\u003c");return`<!DOCTYPE html>
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

  <script id="sld-initial-data" type="application/json" nonce="${e}">${n}</script>
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
</html>`}};var vt=require("child_process"),bt=require("util"),A=I(require("fs")),w=I(require("path"));var J=require("child_process"),ct=require("util"),Fe=I(require("path"));var ye=(0,ct.promisify)(J.execFile),ee=["-c","core.quotepath=false","--literal-pathspecs"];function dt(t){return t.startsWith("R")||t.startsWith("C")}function lt(t){return t.startsWith("D")}function Wt(t){try{let e=(0,J.execFileSync)("git",["rev-parse","--show-toplevel"],{cwd:t,encoding:"utf8"}).trim();if(e)return Fe.resolve(e)}catch{}return t}async function zt(t){try{let{stdout:e}=await ye("git",["rev-parse","--show-toplevel"],{cwd:t,encoding:"utf8"}),i=e.trim();if(i)return Fe.resolve(i)}catch{}return t}function pt(t){let e=Wt(t),i;try{i=(0,J.execFileSync)("git",[...ee,"diff","--cached","-z","--name-status"],{cwd:e,encoding:"utf8",maxBuffer:10*1024*1024})}catch(r){return{status:"ERROR",findings:[],error:`git diff --cached failed: ${r.message||String(r)}`}}let n=i.split("\0").filter(Boolean),s=[],o=0;for(let r=0;r<n.length;){let c=n[r],l=n[r+1],u=2;dt(c)&&n[r+2]!==void 0&&(l=n[r+2],u=3),r+=u;let a=l.replace(/\\/g,"/");if(a==="/dev/null"||lt(c))continue;let p;try{p=(0,J.execFileSync)("git",[...ee,"show",`:${a}`],{cwd:e,encoding:"utf8",maxBuffer:10*1024*1024})}catch(h){return{status:"ERROR",findings:s,error:`Could not read staged blob for '${a}': ${h.message||String(h)}`,filesScanned:o}}let g=new Set;try{let h=(0,J.execFileSync)("git",[...ee,"diff","--cached","-U0","--",a],{cwd:e,encoding:"utf8",maxBuffer:10485760}),S=/^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/gm,R;for(;(R=S.exec(h))!==null;){let x=parseInt(R[1],10),M=R[2]!==void 0?parseInt(R[2],10):1;for(let y=0;y<M;y++)g.add(x+y)}}catch(h){return{status:"ERROR",findings:s,error:`Could not determine staged diff for '${a}': ${h.message||String(h)}`,filesScanned:o}}if(g.size===0)continue;let f=re(p,a,{workspaceRoot:e});for(let h of f)g.has(h.line)&&s.push(h);o++}return s.length>0?{status:"FINDINGS",findings:s,filesScanned:o}:{status:"CLEAN",findings:[],filesScanned:o}}async function ut(t){let e=await zt(t),i;try{let{stdout:r}=await ye("git",[...ee,"diff","--cached","-z","--name-status"],{cwd:e,encoding:"utf8",maxBuffer:10485760});i=r}catch(r){return{status:"ERROR",findings:[],error:`git diff --cached failed: ${r.message||String(r)}`}}let n=i.split("\0").filter(Boolean),s=[],o=0;for(let r=0;r<n.length;){let c=n[r],l=n[r+1],u=2;dt(c)&&n[r+2]!==void 0&&(l=n[r+2],u=3),r+=u;let a=l.replace(/\\/g,"/");if(a==="/dev/null"||lt(c))continue;let p;try{let{stdout:h}=await ye("git",[...ee,"show",`:${a}`],{cwd:e,encoding:"utf8",maxBuffer:10485760});p=h}catch(h){return{status:"ERROR",findings:s,error:`Could not read staged blob for '${a}': ${h.message||String(h)}`,filesScanned:o}}let g=new Set;try{let{stdout:h}=await ye("git",[...ee,"diff","--cached","-U0","--",a],{cwd:e,encoding:"utf8",maxBuffer:10485760}),S=/^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/gm,R;for(;(R=S.exec(h))!==null;){let x=parseInt(R[1],10),M=R[2]!==void 0?parseInt(R[2],10):1;for(let y=0;y<M;y++)g.add(x+y)}}catch(h){return{status:"ERROR",findings:s,error:`Could not determine staged diff for '${a}': ${h.message||String(h)}`,filesScanned:o}}if(g.size===0)continue;let f=re(p,a,{workspaceRoot:e});for(let h of f)g.has(h.line)&&s.push(h);o++}return s.length>0?{status:"FINDINGS",findings:s,filesScanned:o}:{status:"CLEAN",findings:[],filesScanned:o}}var gt=["LOW","MEDIUM","HIGH","CRITICAL"],De={LOW:1,MEDIUM:2,HIGH:3,CRITICAL:4},z="HIGH";function mt(t,e=z){return(De[t]||0)>=(De[e]||De.CRITICAL)}var ae="# [SLD_HOOK_MANAGED]";function ft(t=z,e){let i=gt.includes(t)?t:z,n=e?e.replace(/\\/g,"/"):"",s=n?n.replace(/'/g,"'\\''"):"",o=n?`# Scanner pinned to bundled CLI path
PINNED_CLI='${s}'
if [ -n "$PINNED_CLI" ] && [ -f "$PINNED_CLI" ]; then
  node "$PINNED_CLI" scan --staged --fail-on "$SLD_FAIL_ON"
  SCAN_STATUS=$?
elif command -v secret-leak-detector >/dev/null 2>&1; then
  secret-leak-detector scan --staged --fail-on "$SLD_FAIL_ON"
  SCAN_STATUS=$?
else
  echo ""
  echo "\u274C COMMIT BLOCKED (fail-closed): Secret Leak Detector scanner is unavailable."
  echo "   Pinned CLI ($PINNED_CLI) not found and no global CLI available."
  echo "   Staged changes could not be verified secret-free, so the commit was refused."
  exit 2
fi`:`# Scanner determined from environment or global binary (never ./dist/cli.js relative to repo)
if [ -n "$SLD_CLI_PATH" ] && [ -f "$SLD_CLI_PATH" ]; then
  node "$SLD_CLI_PATH" scan --staged --fail-on "$SLD_FAIL_ON"
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
${ae}
# Secret Leak Detector Pre-Commit Hook
# Intercepts git commit and blocks unredacted credentials before they leave the machine.
#
# Severity policy (single source of truth: src/core/policy.ts):
#   Blocks findings at ${i} and above (LOW < MEDIUM < HIGH < CRITICAL).
#   Lower tiers are reported but do not block.
#
# Fail-closed: if the scanner cannot be executed, the commit is BLOCKED.
SLD_FAIL_ON="${i}"

echo "\u{1F510} [Secret Leak Detector] Inspecting staged changes for credentials..."

${o}

if [ "$SCAN_STATUS" -eq 1 ]; then
  echo ""
  echo "\u274C COMMIT BLOCKED: Secret Leak Detector detected credentials in staged files!"
  echo "Please rotate the secret or migrate it to an environment variable."
  exit 1
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
`}var ht=(0,bt.promisify)(vt.execFile),ke=class{workspaceRoot;cliPath;constructor(e,i){if(this.workspaceRoot=e,i&&A.existsSync(i))this.cliPath=i;else if(process.env.SLD_CLI_PATH&&A.existsSync(process.env.SLD_CLI_PATH))this.cliPath=process.env.SLD_CLI_PATH;else{let n=[w.resolve(__dirname,"cli.js"),w.resolve(__dirname,"../cli/index.js"),w.resolve(__dirname,"../../dist/cli.js")];this.cliPath=n.find(s=>A.existsSync(s))}}async isGitRepo(){try{return await ht("git",["rev-parse","--is-inside-work-tree"],{cwd:this.workspaceRoot}),!0}catch{return!1}}async scanStagedChanges(){return ut(this.workspaceRoot)}scanStagedChangesSync(){return pt(this.workspaceRoot)}formatTerminalBlockedMessage(e){let n=e.filter(d=>d.risk==="CRITICAL")[0]||e[0],s=typeof n.remediation=="string"?n.remediation:n.remediation?.steps?.join(`
`)||"Rotate and move to .env",o=n.evidence?.items?.map(d=>`  - [${d.confidenceImpact>=0?"+":""}${d.confidenceImpact}] ${d.description}`).join(`
`)||n.signals?.map(d=>`  - ${d}`).join(`
`)||"  - Known pattern match",r=n.riskAssessment?.blastRadius?`${n.riskAssessment.blastRadius.level} (${n.riskAssessment.blastRadius.summary})`:"Local Working Tree";return`
============================================================
\u274C COMMIT BLOCKED BY SECRET LEAK DETECTOR
============================================================
\u{1F6A8} Security Risk: Hard-coded secret detected before commit!

Finding Details:
------------------------------------------------------------
\u2022 Type:        ${n.type}
\u2022 Provider:    ${n.provider}
\u2022 File:        ${n.file} (Line ${n.line})
\u2022 Secret:      ${n.redactedSecret}
\u2022 Risk Level:  ${n.risk} (Score: ${n.riskAssessment?.score??95}/100)
\u2022 Confidence:  ${n.confidence}%
\u2022 Blast Radius: ${r}

Evidence & Signals Detected:
${o}

Recommended Remediation:
------------------------------------------------------------
${s}

Example Fix:
  ${n.exampleFix||n.remediation?.replacementCode}

After fixing:
  1. Replace the secret in ${n.file} with an environment variable.
  2. Add the sensitive value to your local .env (ensure .env is in .gitignore!).
  3. Run 'git add ${n.file}'
  4. Run your 'git commit' again.
============================================================
`}async resolveHooksDir(){try{let{stdout:e}=await ht("git",["rev-parse","--git-path","hooks"],{cwd:this.workspaceRoot}),i=e.trim();return w.isAbsolute(i)?i:w.resolve(this.workspaceRoot,i)}catch{return w.join(this.workspaceRoot,".git","hooks")}}async installPreCommitHook(e){if(!await this.isGitRepo())return{success:!1,message:"Workspace is not a Git repository."};let i=await this.resolveHooksDir();if(!A.existsSync(i))try{A.mkdirSync(i,{recursive:!0})}catch(u){return{success:!1,message:`Could not create hooks directory (${i}): ${u}`}}let n=w.join(i,"pre-commit"),s=Date.now(),o=w.join(i,`pre-commit.sld-backup.${s}`),r=w.join(i,"pre-commit.sld-backup.latest"),c=ae;if(A.existsSync(n))try{let u=A.readFileSync(n,"utf8");u.includes(c)||(A.writeFileSync(o,u,{mode:493}),A.writeFileSync(r,o,"utf8"))}catch(u){return{success:!1,message:`Could not backup existing hook: ${u}`}}let d=e||this.cliPath;if(!d||!A.existsSync(d))return{success:!1,message:`Cannot install pre-commit hook: bundled CLI binary not found at '${d||"undefined"}'. Installation aborted.`};/[\/\\](?:_npx|Temp|tmp)[\/\\]/i.test(d)&&console.warn(`\u26A0\uFE0F Warning: Pre-commit hook is pinning a temporary/npx CLI path: '${d}'. This path may be deleted automatically by your system. Consider installing secret-leak-detector globally or locally.`);let l=ft(z,d);try{return A.writeFileSync(n,l,{mode:493}),{success:!0,message:`Pre-commit hook successfully installed to ${n}`}}catch(u){return{success:!1,message:`Failed to write hook file: ${u}`}}}async ensureHookIsPinned(e){if(!e||!A.existsSync(e)||!await this.isGitRepo())return!1;let i=await this.resolveHooksDir(),n=w.join(i,"pre-commit");if(!A.existsSync(n))return!1;try{let s=A.readFileSync(n,"utf8");if(!s.includes(ae))return!1;let o=e.replace(/\\/g,"/");if(!s.includes(o))return(await this.installPreCommitHook(e)).success}catch{return!1}return!0}async uninstallPreCommitHook(){let e=await this.resolveHooksDir(),i=w.join(e,"pre-commit"),n=w.join(e,"pre-commit.sld-backup.latest");if(!A.existsSync(i))return{success:!0,message:"No pre-commit hook found to uninstall."};try{if(!A.readFileSync(i,"utf8").includes(ae))return{success:!1,message:"Existing pre-commit hook is not managed by Secret Leak Detector; refusing to delete user hook."};if(A.existsSync(n)){let o=A.readFileSync(n,"utf8").trim(),r=w.resolve(o),c=w.resolve(e),d=w.basename(r);if(w.dirname(r)===c&&/^pre-commit\.sld-backup\.\d+$/.test(d)&&A.existsSync(r))return A.copyFileSync(r,i),A.unlinkSync(r),A.unlinkSync(n),{success:!0,message:"Uninstalled SLD hook and restored original pre-commit hook."};try{A.unlinkSync(n)}catch{}}return A.unlinkSync(i),{success:!0,message:"Removed Secret Leak Detector pre-commit hook."}}catch(s){return{success:!1,message:`Failed to uninstall hook: ${s.message}`}}}};var N;function Ht(t){N=m.window.createOutputChannel("Secret Leak Detector"),t.subscriptions.push(N),N.appendLine("\u{1F510} [Secret Leak Detector] Extension activated.");let e=new he;t.subscriptions.push(e),t.subscriptions.push(m.languages.registerCodeActionsProvider({scheme:"file"},new Q(e),{providedCodeActionKinds:Q.providedCodeActionKinds}));let i=new ve,n=new be;m.window.registerTreeDataProvider("secret-leak-detector.findingsView",i),m.window.registerTreeDataProvider("secret-leak-detector.overviewView",n);let s=m.workspace.workspaceFolders?.[0],o=s?s.uri.fsPath:process.cwd(),r=new ke(o);e.onFindingsChanged(a=>{i.updateFindings(a),n.update(a.length,!0),q.currentPanel&&q.currentPanel.updateFindings(a)});let c=()=>m.workspace.getConfiguration("secretLeakDetector");function d(){let p=c().get("minEntropy");e.setMinEntropy(typeof p=="number"&&p>0?p:void 0);let g=t.workspaceState.get("ignoredFindings",[]);e.setIgnoredFindings(g)}d();let l=yt.join(t.extensionPath,"dist","cli.js");kt.existsSync(l)&&r.ensureHookIsPinned(l).catch(()=>{}),t.subscriptions.push(m.workspace.onDidChangeConfiguration(a=>{a.affectsConfiguration("secretLeakDetector")&&(d(),m.window.activeTextEditor&&e.scanDocument(m.window.activeTextEditor.document))})),m.window.activeTextEditor&&e.scanDocument(m.window.activeTextEditor.document),t.subscriptions.push(m.workspace.onDidSaveTextDocument(a=>{c().get("enableRealtimeScanning",!0)&&e.scanDocument(a)})),t.subscriptions.push(m.workspace.onDidOpenTextDocument(a=>{c().get("enableRealtimeScanning",!0)&&e.scanDocument(a)}));let u=new Map;t.subscriptions.push(m.workspace.onDidChangeTextDocument(a=>{if(!c().get("enableRealtimeScanning",!0))return;let p=a.document.uri.toString(),g=u.get(p);g&&clearTimeout(g);let f=setTimeout(()=>{e.scanDocument(a.document),u.delete(p)},350);u.set(p,f)})),t.subscriptions.push(m.workspace.onDidDeleteFiles(a=>{a.files.forEach(p=>e.removeDocument(p))})),t.subscriptions.push(m.commands.registerCommand("secret-leak-detector.scanWorkspace",async()=>{await m.window.withProgress({location:m.ProgressLocation.Notification,title:"\u{1F510} Scanning workspace for secret leaks...",cancellable:!1},async a=>{let g=`{${c().get("excludeGlobs",[]).join(",")}}`,f=1e3,h=await m.workspace.findFiles("**/*",g,f),S=[],R=0,x=0;for(let $ of h)try{if((await m.workspace.fs.stat($)).size>5*1024*1024){x++;continue}let v=await m.workspace.openTextDocument($),k=e.scanDocument(v);S.push(...k),R++}catch{x++}let M=h.length>=f,y=`Scanned ${R} files.`;if(M&&(y+=` \u26A0\uFE0F Scan was capped at ${f} files.`),x>0&&(y+=` (${x} large or binary files skipped)`),S.length===0)m.window.showInformationMessage(`\u2705 Scan complete: ${y} No secrets or credentials detected!`);else{let $=S.filter(C=>C.risk==="CRITICAL").length;m.window.showErrorMessage(`\u{1F6A8} Found ${S.length} leaked secret(s) (${$} Critical)! ${y}`,"Open Dashboard","View Findings").then(C=>{C==="Open Dashboard"?m.commands.executeCommand("secret-leak-detector.openDashboard"):C==="View Findings"&&m.commands.executeCommand("workbench.view.extension.secret-leak-detector-sidebar")})}})})),t.subscriptions.push(m.commands.registerCommand("secret-leak-detector.scanStaged",async()=>{N.clear(),N.appendLine("\u{1F510} [Secret Leak Detector] Scanning Git staged changes..."),N.show(!0);let a=c().get("blockGitCommits",!0),p=await r.scanStagedChanges();if(p.status==="ERROR"){N.appendLine(`\u274C [Secret Leak Detector] Scan error: ${p.error}`),a?m.window.showErrorMessage(`\u274C COMMIT GATE BLOCKED: Git security scan failed (${p.error}). Failing closed for safety.`,"View Output"):m.window.showWarningMessage(`\u26A0\uFE0F Git scan encountered an error: ${p.error}`);return}if(p.status==="CLEAN"){N.appendLine("\u2705 All staged changes are clean! No credentials detected."),m.window.showInformationMessage("\u2705 Git staged changes are safe to commit.");return}let g=p.findings,f=g.filter(x=>mt(x.risk,z)),h=r.formatTerminalBlockedMessage(f.length>0?f:g);N.appendLine(h);let R=a&&f.length>0?`\u274C COMMIT BLOCKED: ${f.length} secret(s) at or above ${z} detected in staged changes!`:`\u26A0\uFE0F WARNING: ${g.length} secret(s) detected in staged changes (none block at the ${z} threshold).`;m.window.showErrorMessage(R,"Open Dashboard","View Output").then(x=>{x==="Open Dashboard"&&q.createOrShow(t.extensionUri,g)})})),t.subscriptions.push(m.commands.registerCommand("secret-leak-detector.openDashboard",()=>{q.createOrShow(t.extensionUri,e.getAllFindings())})),t.subscriptions.push(m.commands.registerCommand("secret-leak-detector.installGitHook",async()=>{let a=await r.installPreCommitHook();a.success?m.window.showInformationMessage(`\u{1F6E1}\uFE0F ${a.message}`):m.window.showErrorMessage(`Failed to install hook: ${a.message}`)})),t.subscriptions.push(m.commands.registerCommand("secret-leak-detector.uninstallGitHook",async()=>{let a=await r.uninstallPreCommitHook();a.success?m.window.showInformationMessage(`\u{1F6E1}\uFE0F ${a.message}`):m.window.showErrorMessage(`Failed to uninstall hook: ${a.message}`)})),t.subscriptions.push(m.commands.registerCommand("secret-leak-detector.ignoreFinding",async a=>{let p=a;if(!p){let f=e.getAllFindings();if(f.length===0){m.window.showInformationMessage("No active findings to ignore.");return}let h=await m.window.showQuickPick(f.map(S=>({label:`${S.type} (${S.file}:${S.line})`,description:S.redactedSecret,id:S.id})),{placeHolder:"Select a finding to ignore (suppress as false-positive)"});if(!h)return;p=h.id}e.ignoreFinding(p);let g=e.getIgnoredFindings();await t.workspaceState.update("ignoredFindings",g),m.window.showInformationMessage("\u{1F6E1}\uFE0F Finding marked as false-positive and suppressed.")})),t.subscriptions.push(m.commands.registerCommand("secret-leak-detector.remediateFinding",async(a,p,g)=>{await Q.executeRemediation(a,p,g)})),t.subscriptions.push(m.commands.registerCommand("secret-leak-detector.clearFindings",()=>{e.clear(),m.window.showInformationMessage("Secret Leak Detector: All findings cleared.")})),r.isGitRepo().then(a=>{n.update(0,a)})}function Gt(){N&&N.dispose()}0&&(module.exports={activate,deactivate});
