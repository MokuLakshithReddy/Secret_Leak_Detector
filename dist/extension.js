"use strict";var Ft=Object.create;var Se=Object.defineProperty;var Dt=Object.getOwnPropertyDescriptor;var Lt=Object.getOwnPropertyNames;var $t=Object.getPrototypeOf,Nt=Object.prototype.hasOwnProperty;var Ot=(t,e)=>{for(var n in e)Se(t,n,{get:e[n],enumerable:!0})},Ze=(t,e,n,i)=>{if(e&&typeof e=="object"||typeof e=="function")for(let s of Lt(e))!Nt.call(t,s)&&s!==n&&Se(t,s,{get:()=>e[s],enumerable:!(i=Dt(e,s))||i.enumerable});return t};var _=(t,e,n)=>(n=t!=null?Ft($t(t)):{},Ze(e||!t||!t.__esModule?Se(n,"default",{value:t,enumerable:!0}):n,t)),Mt=t=>Ze(Se({},"__esModule",{value:!0}),t);var on={};Ot(on,{activate:()=>nn,deactivate:()=>sn});module.exports=Mt(on);var f=_(require("vscode")),he=_(require("path")),U=_(require("fs"));var E=_(require("vscode"));var ie=_(require("path")),yt=_(require("crypto"));var Ye=[{id:"aws-access-key",name:"AWS Access Key ID",provider:"Amazon Web Services",pattern:/\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b/g,baseConfidence:98,baseRiskWeight:95,signals:["AWS IAM standard 20-character key prefix (AKIA/ASIA/ABIA/ACCA)","Deterministic uppercase alphanumeric structure","Direct cloud resource control & hijacking capability"],suggestedEnvName:()=>"AWS_ACCESS_KEY_ID",remediationInstructions:["Revoke the exposed Access Key ID immediately in AWS IAM Management Console.","Check AWS CloudTrail logs for unauthorized API calls originated by this key.","Transition to IAM Roles for Amazon EC2 or AWS IAM Identity Center (SSO).","Never store access keys in source code; use AWS_ACCESS_KEY_ID environment variable."]},{id:"aws-secret-key",name:"AWS Secret Access Key",provider:"Amazon Web Services",pattern:/["']?(?:aws_secret_access_key|aws_secret_key|secret_access_key)["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?(?:[\s\r\n;,)]|$)/gi,baseConfidence:94,baseRiskWeight:95,minEntropy:4.1,signals:["Contextual AWS credential parameter match","High-entropy 40-character Base64 payload","Pairs with AWS Access Key for root/IAM API authentication"],suggestedEnvName:()=>"AWS_SECRET_ACCESS_KEY",remediationInstructions:["Rotate the key pair immediately in the AWS IAM Console.","Audit AWS KMS and S3 bucket accesses during exposure window.","Store secrets in AWS Secrets Manager or Parameter Store."]},{id:"github-pat",name:"GitHub Personal Access Token",provider:"GitHub",pattern:/\b(gh[pousr]_[A-Za-z0-9_]{36,255}|github_pat_[A-Za-z0-9_]{82})\b/g,baseConfidence:99,baseRiskWeight:95,signals:["Official GitHub token format prefix (ghp_, gho_, ghu_, ghs_, github_pat_)","Deterministic token structure and length","Permits repository code modification, workflow execution, or release poisoning"],suggestedEnvName:()=>"GITHUB_TOKEN",remediationInstructions:["Revoke token immediately at https://github.com/settings/tokens.","Check GitHub Security Audit Log for unauthorized repository clones or writes.","Use GitHub fine-grained PATs with scoped repository permissions.","Use GitHub Actions secrets rather than personal tokens for CI/CD."]},{id:"google-api-key",name:"Google Cloud / Gemini API Key",provider:"Google Cloud",pattern:/\b(AIza[0-9A-Za-z_-]{34,35})\b/g,baseConfidence:96,baseRiskWeight:90,minEntropy:3.5,signals:["Google standard AIza service key signature","Fixed 39-character alphanumeric structure","Access to Google Cloud Platform APIs and billing services"],suggestedEnvName:()=>"GEMINI_API_KEY",remediationInstructions:["Restrict or delete the API key in Google Cloud Console Credentials page.","Apply API restrictions (e.g. restrict solely to Generative Language API).","Apply HTTP referrer or IP address restrictions.","Store in GEMINI_API_KEY environment variable."]},{id:"google-oauth-token",name:"Google OAuth Access Token",provider:"Google Cloud",pattern:/\b(ya29\.[0-9a-zA-Z_-]{50,150})\b/g,baseConfidence:98,baseRiskWeight:92,minEntropy:4,signals:["Google OAuth bearer access token prefix (ya29.)","Direct user account delegation & Cloud Platform API access"],suggestedEnvName:()=>"GOOGLE_OAUTH_TOKEN",remediationInstructions:["Revoke token via Google Cloud IAM or OAuth2 token revocation endpoint.","Store OAuth refresh tokens securely in credential vaults."]},{id:"openai-api-key",name:"OpenAI API Key",provider:"OpenAI",pattern:/\b(sk-(?:proj|admin|svcacct)-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{20,48})\b/g,baseConfidence:97,baseRiskWeight:92,minEntropy:4,signals:["OpenAI official secret prefix (sk-proj- or sk-)","High Shannon entropy key payload","Direct account credit exhaustion and model theft risk"],suggestedEnvName:()=>"OPENAI_API_KEY",remediationInstructions:["Revoke key at https://platform.openai.com/api-keys.","Verify credit consumption in OpenAI usage dashboard.","Inject credentials using OPENAI_API_KEY environment variable."]},{id:"anthropic-api-key",name:"Anthropic Claude API Key",provider:"Anthropic",pattern:/\b(sk-ant-[A-Za-z0-9_-]{30,})\b/g,baseConfidence:98,baseRiskWeight:92,minEntropy:3.8,signals:["Anthropic official secret token signature (sk-ant-)","High entropy cryptographic token payload","Direct Claude model API billing access"],suggestedEnvName:()=>"ANTHROPIC_API_KEY",remediationInstructions:["Revoke the API key in Anthropic Console.","Generate replacement key with spend limit configured.","Inject via ANTHROPIC_API_KEY environment variable."]},{id:"huggingface-token",name:"Hugging Face Access Token",provider:"Hugging Face",pattern:/\b(hf_[A-Za-z0-9]{34})\b/g,baseConfidence:98,baseRiskWeight:88,minEntropy:3.8,signals:["Hugging Face user access token format (hf_ prefix + 34 chars)","Grants access to gated AI models, private repositories, and inference endpoints"],suggestedEnvName:()=>"HF_TOKEN",remediationInstructions:["Revoke token immediately at https://huggingface.co/settings/tokens.","Audit access logs for unauthorized model downloads.","Inject credentials using the HF_TOKEN environment variable."]},{id:"stripe-secret-key",name:"Stripe Secret Key",provider:"Stripe",pattern:/\b((?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,100})\b/g,baseConfidence:97,baseRiskWeight:96,signals:["Stripe signature prefix (sk_live / rk_live / sk_test)","Financial transaction and customer credit card access","High financial liability and compliance breach"],suggestedEnvName:()=>"STRIPE_SECRET_KEY",remediationInstructions:["Roll API key immediately in Stripe Dashboard > Developers > API keys.","Audit recent transactions and payout bank account modifications.","Never bundle Stripe secret keys in frontend or mobile client builds."]},{id:"slack-bot-token",name:"Slack OAuth / Bot Token",provider:"Slack",pattern:/\b(xox[baprs]-[0-9A-Za-z-]{10,72})\b/g,baseConfidence:95,baseRiskWeight:82,signals:["Slack OAuth bot/user prefix (xoxb/xoxp/xoxa)","Internal company communications and workspace access"],suggestedEnvName:()=>"SLACK_BOT_TOKEN",remediationInstructions:["Revoke token in api.slack.com/apps.","Re-install app with minimal necessary OAuth scopes."]},{id:"slack-webhook",name:"Slack Incoming Webhook URL",provider:"Slack",pattern:/(https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9_]{8,12}\/B[A-Z0-9_]{8,12}\/[A-Za-z0-9_]{24})/g,baseConfidence:98,baseRiskWeight:78,signals:["Slack Incoming Webhook URL structure","Enables unauthorized message spoofing and channel phishing"],suggestedEnvName:()=>"SLACK_WEBHOOK_URL",remediationInstructions:["Delete the exposed webhook URL in Slack App settings.","Generate a new webhook URL and store in SLACK_WEBHOOK_URL."]},{id:"azure-storage-key",name:"Azure Shared Storage Key",provider:"Microsoft Azure",pattern:/["']?(?:AccountKey|azure_secret|azure_key)["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{86,88}==)(?:["';,\s\r\n)]|$)/gi,baseConfidence:93,baseRiskWeight:90,minEntropy:4.2,signals:["Azure storage account key signature (86-88 chars base64 with == padding)","Full administrative access to Azure Blob/Queue/Table storage"],suggestedEnvName:()=>"AZURE_STORAGE_KEY",remediationInstructions:["Regenerate storage key in Azure Portal.","Adopt Azure Managed Identity or Microsoft Entra ID authentication instead."]},{id:"azure-ad-client-secret",name:"Azure Active Directory Client Secret",provider:"Microsoft Azure",pattern:/["']?(?:azure[_-]?(?:client|ad|app)?[_-]?secret|client[_-]?secret)\s*[:=]\s*["']?([a-zA-Z0-9_~.-]{34,44})["']?(?:[\s\r\n;,)]|$)/gi,baseConfidence:90,baseRiskWeight:90,minEntropy:3.8,signals:["Azure AD / Entra ID client secret assignment pattern","Application impersonation and tenant directory access"],suggestedEnvName:()=>"AZURE_CLIENT_SECRET",remediationInstructions:["Revoke and rotate the client secret in Azure App Registrations portal.","Migrate to Managed Identity or Federated Credentials where possible."]},{id:"discord-bot-token",name:"Discord Bot Token",provider:"Discord",pattern:/\b([M-Z][A-Za-z0-9]{23,27}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,38})\b/g,baseConfidence:98,baseRiskWeight:88,signals:["Official Discord bot token format (ID.HMAC.Signature)","Complete bot control, server membership manipulation, and message reading"],suggestedEnvName:()=>"DISCORD_BOT_TOKEN",remediationInstructions:["Reset token in Discord Developer Portal > Bot > Reset Token.","Store in DISCORD_BOT_TOKEN environment variable."]},{id:"telegram-bot-token",name:"Telegram Bot Token",provider:"Telegram",pattern:/\b([0-9]{8,10}:[a-zA-Z0-9_-]{35})\b/g,baseConfidence:96,baseRiskWeight:85,signals:["Telegram Bot API token format (Numeric ID : 35-character secret)","Direct control of Telegram bot communications and webhooks"],suggestedEnvName:()=>"TELEGRAM_BOT_TOKEN",remediationInstructions:["Revoke and reissue the token using Telegram @BotFather (/revoke).","Store in TELEGRAM_BOT_TOKEN environment variable."]},{id:"pypi-api-token",name:"PyPI API Token",provider:"PyPI",pattern:/\b(pypi-[A-Za-z0-9_-]{50,150})\b/g,baseConfidence:99,baseRiskWeight:92,signals:["Official PyPI package index upload token prefix (pypi-)","Supply chain compromise and malicious Python package publication risk"],suggestedEnvName:()=>"PYPI_TOKEN",remediationInstructions:["Revoke the token immediately at https://pypi.org/manage/account/tokens/.","Inspect published package versions for tampering."]},{id:"shopify-access-token",name:"Shopify Admin / Storefront Access Token",provider:"Shopify",pattern:/\b(shp(?:at|ca|pa)_[a-fA-F0-9]{32})\b/g,baseConfidence:98,baseRiskWeight:92,signals:["Official Shopify access token prefix (shpat_, shpca_, shppa_)","E-commerce store data, customer orders, and payment configuration access"],suggestedEnvName:()=>"SHOPIFY_API_KEY",remediationInstructions:["Revoke the token in Shopify Admin > Apps and sales channels.","Audit store access and customer data logs."]},{id:"digitalocean-pat",name:"DigitalOcean Personal Access Token",provider:"DigitalOcean",pattern:/\b(dop_v1_[a-f0-9]{64})\b/g,baseConfidence:99,baseRiskWeight:92,signals:["Official DigitalOcean v1 token format (dop_v1_ prefix + 64 hex characters)","Droplet creation, destruction, and Cloud infrastructure control"],suggestedEnvName:()=>"DIGITALOCEAN_TOKEN",remediationInstructions:["Revoke the token in DigitalOcean Control Panel > API > Tokens.","Check active Droplets and firewall configurations for unauthorized changes."]},{id:"mailgun-api-key",name:"Mailgun Private API Key",provider:"Mailgun",pattern:/\b(key-[0-9a-zA-Z]{32})\b/g,baseConfidence:96,baseRiskWeight:85,signals:["Mailgun standard private API key signature (key- + 32 chars)","Bulk email dispatch and communication channel spoofing"],suggestedEnvName:()=>"MAILGUN_API_KEY",remediationInstructions:["Rotate key in Mailgun Dashboard > API Security.","Store in MAILGUN_API_KEY environment variable."]},{id:"square-access-token",name:"Square Access Token",provider:"Square",pattern:/\b(sq0atp-[0-9A-Za-z_-]{22}|sq0csp-[0-9A-Za-z_-]{43}|EAAA[a-zA-Z0-9_-]{60})\b/g,baseConfidence:97,baseRiskWeight:94,signals:["Square OAuth / production access token prefix (sq0atp-, sq0csp-, EAAA)","Payment processing, merchant account, and customer financial data access"],suggestedEnvName:()=>"SQUARE_ACCESS_TOKEN",remediationInstructions:["Revoke token in Square Developer Dashboard > OAuth settings.","Audit payment ledger and API access history."]},{id:"private-key",name:"Cryptographic Private Key (PEM)",provider:"Cryptography",pattern:/(-----BEGIN (?:[A-Z0-9_-]+ )*PRIVATE KEY(?: BLOCK)?-----(?:(?!-----BEGIN)[\s\S]){1,8192}?-----END (?:[A-Z0-9_-]+ )*PRIVATE KEY(?: BLOCK)?-----)/g,baseConfidence:100,baseRiskWeight:100,signals:["Standard PEM container header and footer","Unencrypted cryptographic private key","Total server impersonation, SSH compromise, or TLS decryption risk"],suggestedEnvName:()=>"PRIVATE_KEY_PATH",remediationInstructions:["Immediately decommission this private key pair.","Remove public key counterpart from all servers authorized_keys.","Never commit private keys to version control; use SSH agents or secret vaults."]},{id:"database-url",name:"Database Connection String with Credentials",provider:"Database",pattern:/\b((?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis):\/\/[^:\s'"@]+:([^@\s'"]+)@([a-zA-Z0-9_.-]+(?::[0-9]+)?(?:\/[^\s'"`;]*)?))/gi,baseConfidence:92,baseRiskWeight:88,minEntropy:3.2,signals:["Database connection URL containing embedded user:password credentials","Direct data exfiltration, deletion, or ransomware risk"],suggestedEnvName:()=>"DATABASE_URL",remediationInstructions:["Rotate the database user password immediately on the database server.","Migrate connection string to DATABASE_URL environment variable.","Enable SSL/TLS requirement and VPC network access controls."]},{id:"url-credentials",name:"URL with Embedded Credentials",provider:"Generic Credential",pattern:/\b(https?:\/\/[^:\s'"\/?#@]+:([^@\s'"\/?#]+)@([a-zA-Z0-9_.-]+(?::[0-9]+)?(?:\/[^\s'"`;]*)?))/gi,baseConfidence:90,baseRiskWeight:85,minEntropy:3,signals:["HTTP/HTTPS URL containing embedded user:password or user:token credentials","Authentication credential transmission in URL plain text"],suggestedEnvName:()=>"API_ENDPOINT_URL",remediationInstructions:["Remove credentials from URL; pass authentication in Authorization headers.","Rotate exposed password or access token immediately."]},{id:"bearer-token",name:"Authorization Bearer Token",provider:"Auth / Identity",pattern:/(?:Authorization|auth)\s*[:=]\s*["']?Bearer\s+([A-Za-z0-9_.~+/-]{20,255})["']?/gi,baseConfidence:92,baseRiskWeight:85,minEntropy:3.5,signals:["HTTP Authorization header with static Bearer token literal","API session impersonation and service authentication bypass"],suggestedEnvName:()=>"AUTH_TOKEN",remediationInstructions:["Revoke the exposed bearer token.","Inject bearer tokens dynamically from environment variables."]},{id:"jwt-token",name:"JSON Web Token (JWT)",provider:"Auth / Identity",pattern:/\b(ey[A-Za-z0-9_-]{15,}\.ey[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{10,})\b/g,baseConfidence:88,baseRiskWeight:75,minEntropy:4.1,signals:["Header.Payload.Signature Base64 tripartite JWT structure","Authentication session hijacking and privilege escalation"],suggestedEnvName:t=>t?.toUpperCase()||"AUTH_TOKEN",remediationInstructions:["Invalidate active sessions / revoke refresh token family in identity provider.","Never hardcode tokens in client or backend source repositories."]},{id:"gitlab-pat",name:"GitLab Personal Access Token",provider:"GitLab",pattern:/\b(glpat-[0-9a-zA-Z_-]{20,40})\b/g,baseConfidence:98,baseRiskWeight:90,signals:["GitLab personal access token prefix (glpat-)","Repository read/write and CI/CD control"],suggestedEnvName:()=>"GITLAB_TOKEN",remediationInstructions:["Revoke token in GitLab User Settings > Access Tokens.","Store in GITLAB_TOKEN environment variable."]},{id:"npm-access-token",name:"npm Access Token",provider:"npm",pattern:/\b(npm_[A-Za-z0-9]{36})\b/g,baseConfidence:99,baseRiskWeight:92,signals:["npm official access token prefix (npm_)","Package publication and account takeover capability"],suggestedEnvName:()=>"NPM_TOKEN",remediationInstructions:["Revoke token immediately at https://www.npmjs.com/settings/tokens.","Store in NPM_TOKEN environment variable."]},{id:"sendgrid-api-key",name:"SendGrid API Key",provider:"SendGrid",pattern:/\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b/g,baseConfidence:99,baseRiskWeight:85,signals:["SendGrid standard tripartite API key (SG.<22>.<43>)","Email spoofing and communication channel hijacking risk"],suggestedEnvName:()=>"SENDGRID_API_KEY",remediationInstructions:["Revoke key in SendGrid dashboard Settings > API Keys.","Store in SENDGRID_API_KEY environment variable."]},{id:"twilio-api-key",name:"Twilio Auth Token / API Secret",provider:"Twilio",pattern:/\b(SK[0-9a-fA-F]{32})\b|["']?(?:twilio[a-z0-9_-]*(?:auth_?token|api_?secret|secret)|(?:auth_?token|api_?secret))\s*[:=]\s*["']?([0-9a-fA-F]{32})["']?(?:[\s\r\n;,)]|$)/gi,baseConfidence:95,baseRiskWeight:90,minEntropy:3.5,signals:["Twilio Auth Token, API Key SID (SK...), or API Secret assignment","32-character hexadecimal secret token","Telephony API and SMS billing access"],suggestedEnvName:()=>"TWILIO_AUTH_TOKEN",remediationInstructions:["Rotate token in Twilio Console.","Store in TWILIO_AUTH_TOKEN environment variable."]},{id:"password-assignment",name:"Password in Source Code",provider:"Generic Credential",pattern:/["']?(?:password|passwd|pwd|db_password|db_pass)["']?\s*[:=]\s*["']?(?!(?:password|passwordRequired|required|required_field|true|false|null|undefined|string|default|changeme|placeholder|example|admin|test)\b)([^"'\r\n\s#;,]{8,64})["']?/gi,baseConfidence:82,baseRiskWeight:80,minEntropy:2.8,signals:["Hard-coded password assignment in code, .env, or YAML","Credential exposure in plain text"],suggestedEnvName:()=>"PASSWORD",remediationInstructions:["Rotate password immediately.","Store password in an environment variable or secrets manager.","Never commit plain passwords to version control."]},{id:"generic-api-key",name:"Generic API Secret Assignment",provider:"Generic Credential",pattern:/["']?(?:api_?key|secret_?key|auth_?token|client_?secret|access_?token|private_?key|jwt_?secret)["']?\s*[:=]\s*["']?(?!(?:process\.env|import\.meta\.env|os\.environ|ENV)\b)([A-Za-z0-9_.~/+=]{20,90})["']?(?:[\s\r\n;,)]|$)/gi,baseConfidence:80,baseRiskWeight:70,minEntropy:3.5,signals:["Sensitive identifier keyword assignment in code, .env, or YAML","High Shannon entropy string literal"],suggestedEnvName:t=>t?t.toUpperCase():"API_KEY",remediationInstructions:["Identify corresponding API provider and rotate credential.","Migrate credential to local .env file (ensure .env is in .gitignore)."]}];var K=_(require("path")),Bt=[/api[_-]?key/i,/secret[_-]?key/i,/access[_-]?token/i,/auth[_-]?token/i,/private[_-]?key/i,/client[_-]?secret/i,/password/i,/credential/i,/session[_-]?token/i,/bearer/i,/aws[_-]?(?:access|secret)/i,/stripe[_-]?(?:secret|key)/i,/github[_-]?(?:token|pat)/i,/slack[_-]?token/i,/db[_-]?pass(?:word)?/i],Wt=[/placeholder/i,/mock/i,/dummy/i,/fake/i,/sample/i,/test[_-]?(?:key|token|id)/i,/demo/i,/insert[_-]?here/i];function zt(t,e){if(e){let n=K.relative(e,t);if(!n.startsWith("..")&&!K.isAbsolute(n))return n.replace(/\\/g,"/")}return K.isAbsolute(t)?K.basename(t):t.replace(/\\/g,"/")}function qe(t,e){let n=zt(t,e).toLowerCase(),i=K.basename(t).toLowerCase(),s=K.extname(t).toLowerCase(),a=/(?:^|\/)(?:tests?|specs?|__tests__|__mocks__|fixtures|mocks)\//i.test(n)||/[._-](?:test|spec)\.[a-z0-9]+$/i.test(i)||/^(?:test|spec)\.[a-z0-9]+$/i.test(i),o=/(?:^|\/)(?:docs|doc|documentation|tutorials|guides)\/|readme\.md|contributing\.md|changelog\.md/i.test(n),r=/(?:^|\/)(?:example|sample|\.example|\.sample)/i.test(n)||/[._-](?:example|sample)\.[a-z0-9]+$/i.test(i),l=/^\.env(?:\.[a-z0-9]+)?$/.test(i)||/(?:^|\/)(?:config|settings|k8s|helm|deploy|tfvars)\//i.test(n)||/(?:^|[._-])(?:config|settings|secret|credential|database|deploy)\.[a-z0-9]+$/i.test(i)||[".env",".yaml",".yml",".json",".toml",".ini",".tf"].includes(s),d=/^\.env/.test(i)||/(?:secret|credential|id_rsa|private_key|keypair|auth_config)/i.test(i);return{fileExtension:s,isConfig:l,isTest:a,isDoc:o,isSensitiveName:d,isExampleOrSample:r}}function Le(t,e){let n=t[e]||"",i=[];for(let m=Math.max(0,e-3);m<e;m++)i.push(t[m]);let s=[];for(let m=e+1;m<Math.min(t.length,e+4);m++)s.push(t[m]);let a,o=n.match(/(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*[:=]/),r=n.match(/["']?([a-zA-Z0-9_$-]+)["']?\s*[:=]/);o?a=o[1]:r&&(a=r[1]);let l=a?Bt.some(m=>m.test(a)):!1,d=a?Wt.some(m=>m.test(a)):!1,g=/[:=]/.test(n),c=/(?:process\.env|os\.environ|dotenv|config|getenv)/i.test(n),p=/(?:authorization|bearer|x-api-key)/i.test(n),u=/^\s*(?:\/\/|#|\/\*|\*|--)/.test(n);return{inferredVariable:a,isSensitiveIdentifier:l,isBenignIdentifier:d,isAssignment:g,isEnvOrConfigAccess:c,isHeaderOrBearer:p,isInComment:u,surroundingBefore:i,matchedLine:n,surroundingAfter:s}}var Ae=/(?:api_?key|secret|token|password|auth|credential|access_?key|private_?key)/i,Je=/(?:console\.(?:log|warn|error|info|debug)|logger\.|print\(|logging\.)/i,Ee=null;try{Ee=require("typescript")}catch{Ee=null}function $e(t,e,n){let i=t[e]||"";if(Ee&&(!n||/\.[jt]sx?$|\.m[jt]s$|\.c[jt]s$/i.test(n))){let a,o;if(t.length>60){let l=Math.max(0,e-30),d=Math.min(t.length,e+30);a=t.slice(l,d).join(`
`),o=e-l}else a=t.join(`
`),o=e;let r=Kt(a,o);if(r)return r}return Ht(i)}function Kt(t,e){try{let d=function(g){if(!l&&!(g.pos>r||g.end<o)&&(i.forEachChild(g,d),!l)){if(g.kind===i.SyntaxKind.BinaryExpression&&(g.operatorToken.kind===i.SyntaxKind.BarBarToken||g.operatorToken.kind===i.SyntaxKind.QuestionQuestionToken)){let c=g.left.getText(s);if(c.includes("process.env")||c.includes("env")||c.toLowerCase().includes("key")){l={variablePath:c,isSensitiveProperty:Ae.test(c),isEnvFallback:!0,isAuthorizationHeader:!1,isLoggingCall:!1,scopeType:"ENV_FALLBACK"};return}}if(g.kind===i.SyntaxKind.PropertyAssignment){let c=g.name.getText(s),p=c,u=g.parent;for(;u;)u.kind===i.SyntaxKind.PropertyAssignment&&u.name?p=`${u.name.getText(s)}.${p}`:u.kind===i.SyntaxKind.VariableDeclaration&&u.name&&(p=`${u.name.getText(s)}.${p}`),u=u.parent;let m=Ae.test(p),h=/authorization|bearer|x-api-key/i.test(c);l={variablePath:p,isSensitiveProperty:m,isEnvFallback:!1,isAuthorizationHeader:h,isLoggingCall:!1,scopeType:h?"HEADER":"OBJECT_PROPERTY"};return}if(g.kind===i.SyntaxKind.CallExpression){let c=g.expression.getText(s);if(Je.test(c)){l={variablePath:c,isSensitiveProperty:!1,isEnvFallback:!1,isAuthorizationHeader:!1,isLoggingCall:!0,scopeType:"FUNCTION_ARG"};return}}if(g.kind===i.SyntaxKind.VariableDeclaration){let c=g.name.getText(s);l={variablePath:c,isSensitiveProperty:Ae.test(c),isEnvFallback:!1,isAuthorizationHeader:!1,isLoggingCall:!1,scopeType:"VARIABLE_DECLARATION"};return}}};var n=d;let i=Ee,s=i.createSourceFile("eval_target.tsx",t,i.ScriptTarget.Latest,!0,i.ScriptKind.TSX),a=s.getLineStarts();if(e>=a.length)return null;let o=a[e],r=e+1<a.length?a[e+1]-1:t.length,l=null;return d(s),l}catch{return null}}function Ht(t){let e=Je.test(t),n=/(?:process\.env\.[A-Za-z0-9_]+|os\.(?:getenv|environ\.get)\([^)]+\))\s*(?:\|\||\?\?)\s*["'][^"']+["']/.test(t),i=/(?:authorization|x-api-key|bearer)\s*[:=]/i.test(t),s=t.match(/([a-zA-Z0-9_$.]+)\s*[:=]\s*["'][^"']+["']/)||t.match(/["']([a-zA-Z0-9_.]+)["']\s*:\s*["'][^"']+["']/),a,o=!1;s&&(a=s[1],o=Ae.test(a));let r="UNKNOWN";return n?r="ENV_FALLBACK":i?r="HEADER":a&&a.includes(".")?r="OBJECT_PROPERTY":a?r="VARIABLE_DECLARATION":e&&(r="FUNCTION_ARG"),{variablePath:a,isSensitiveProperty:o,isEnvFallback:n,isAuthorizationHeader:i,isLoggingCall:e,scopeType:r}}function de(t){if(!t||t.length===0)return 0;let e={};for(let s of t)e[s]=(e[s]||0)+1;let n=0,i=t.length;for(let s in e){let a=e[s]/i;n-=a*Math.log2(a)}return Math.round(n*100)/100}function Ne(t){return/^[0-9a-fA-F]+$/.test(t)?{setName:"HEX",baseSize:16}:/^[A-Za-z0-9+/=_-]+$/.test(t)?{setName:"BASE64",baseSize:64}:/^[A-Za-z0-9]+$/.test(t)?{setName:"ALPHANUMERIC",baseSize:62}:/^[\x20-\x7E]+$/.test(t)?{setName:"ASCII_PRINTABLE",baseSize:95}:{setName:"SPECIAL",baseSize:128}}function Xe(t){if(!t||t.length===0)return 0;let e=de(t),{baseSize:n}=Ne(t),i=Math.log2(n);if(i<=0)return 0;let s=Math.min(1,e/i);return Math.round(s*100)/100}var Gt=[/\bplaceholder\b/i,/\byour[_-]?(?:api)?[_-]?key\b/i,/\byour[_-]?secret\b/i,/\byour[_-]?token\b/i,/\binsert[_-]?here\b/i,/\breplace[_-]?me\b/i,/\benter[_-]?your\b/i,/\bchange[_-]?me\b/i,/\bdummy\b/i,/\bfake[_-]?token\b/i,/xxxx+/i,/\btest[_-]?value\b/i,/AKIAIOSFODNN7EXAMPLE/i,/wJalrXUtnFEMI\/K7MDENG\/bPxRfiCYEXAMPLEKEY/i,/^123456789[0-9]*$/,/^abcdef[a-z0-9]*$/i,/00000000[0-9]*/,/sk_live_example/i,/ghp_example/i,/:\/\/[^:]+:(?:password|secret|changeme|pass|admin|test|postgres|root)@(?:localhost|127\.0\.0\.1)(?::\d+)?\b/i,/:\/\/(?:postgres|root):(postgres|root)@(?:localhost|127\.0\.0\.1)(?::\d+)?\b/i],Vt=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,Ut=/^(?:mock|dummy|placeholder|fake|sample)_(?:key|token|secret|password|pwd|cred)$/i;function Qe(t,e,n){if(/(?:process\.env|import\.meta\.env|os\.environ|ENV[\[\.])/.test(t))return{isFalsePositive:!0,reason:"Environment variable lookup expression, not a hard-coded credential literal",confidencePenalty:100};if(/^(?:passwordRequired|required_field|required|optional|placeholder|changeme|default|test|dummy|example|string|undefined|null)$/i.test(t))return{isFalsePositive:!0,reason:"Common non-secret schema or form attribute value",confidencePenalty:100};for(let s of Gt)if(s.test(t))return{isFalsePositive:!0,reason:`Matched known documentation/placeholder pattern: ${s.source}`,confidencePenalty:100};if(e&&Ut.test(e)&&!(t.startsWith("AKIA")||t.startsWith("ASIA")||t.startsWith("ghp_")||t.startsWith("gho_")||t.startsWith("ghu_")||t.startsWith("ghs_")||t.startsWith("ghr_")||t.startsWith("github_pat_")||t.startsWith("glpat-")||t.startsWith("sk_live_")||t.startsWith("rk_live_")||t.startsWith("xoxb-")||t.startsWith("xoxp-")||t.startsWith("xoxa-")||t.startsWith("xoxr-")||t.startsWith("pypi-")||t.startsWith("dop_v1_")||t.startsWith("shpat_")||t.startsWith("shpca_")||t.startsWith("shppa_")||t.startsWith("ya29.")||t.startsWith("key-")||t.startsWith("sq0atp-")||t.startsWith("sq0csp-")||/^SK[0-9a-fA-F]{32}$/.test(t)||t.includes("-----BEGIN")||t.length>=14&&de(t)>=3.6))return{isFalsePositive:!0,reason:`Variable identifier indicates placeholder: ${e}`,confidencePenalty:100};let i=new Set(t.split("")).size;if(t.length>=10&&i<=3)return{isFalsePositive:!0,reason:"Low character diversity (repetitive filler characters)",confidencePenalty:95};if(Vt.test(t)&&!e?.match(/secret|token|api_?key/i))return{isFalsePositive:!0,reason:"Standard UUID identifier without credential context",confidencePenalty:90};if(n){let s=/(?:docs|documentation|tutorials|guides)\/|readme\.md/i.test(n);if(/(?:example|sample|\.example|\.sample)/i.test(n)&&/example|your_/i.test(t))return{isFalsePositive:!0,reason:"Sample configuration value inside template/example file",confidencePenalty:90};if(s&&!t.startsWith("ghp_")&&!t.startsWith("AKIA"))return{isFalsePositive:!1,confidencePenalty:25}}return{isFalsePositive:!1,confidencePenalty:0}}function et(t){if(!/^(AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}$/.test(t))return{isValid:!1,confidenceBonus:0,reason:"Invalid AWS key length or character set"};let e=t.substring(0,4);return{isValid:!0,confidenceBonus:10,reason:{AKIA:"Standard permanent IAM user access key",ASIA:"Temporary STS session access key",ABIA:"AWS Backup access key",ACCA:"AWS CodeCommit access key"}[e]||"Valid AWS Access Key ID structure"}}function tt(t){let e=/^sk_live_[0-9a-zA-Z]{24,100}$/.test(t)||/^rk_live_[0-9a-zA-Z]{24,100}$/.test(t),n=/^sk_test_[0-9a-zA-Z]{24,100}$/.test(t)||/^rk_test_[0-9a-zA-Z]{24,100}$/.test(t);return!e&&!n?{isValid:!1,confidenceBonus:0,reason:"Does not match official Stripe secret key format"}:{isValid:!0,confidenceBonus:e?12:5,reason:e?"Production live Stripe Secret Key":"Stripe Test API key"}}function nt(t){return/^ghp_[A-Za-z0-9_]{36}$/.test(t)?{isValid:!0,confidenceBonus:12,reason:"GitHub Personal Access Token (Classic)"}:/^gho_[A-Za-z0-9_]{36}$/.test(t)?{isValid:!0,confidenceBonus:10,reason:"GitHub OAuth Access Token"}:/^ghs_[A-Za-z0-9_]{36}$/.test(t)?{isValid:!0,confidenceBonus:10,reason:"GitHub Server-to-server token"}:/^github_pat_[A-Za-z0-9_]{82}$/.test(t)?{isValid:!0,confidenceBonus:15,reason:"GitHub Fine-Grained Personal Access Token"}:{isValid:!1,confidenceBonus:0,reason:"Invalid GitHub token prefix or length"}}function it(t){let e=t.split(".");if(e.length!==3)return{isValid:!1,confidenceBonus:0,reason:"Not a 3-part dot-separated JWT"};try{let n=Buffer.from(e[0],"base64url").toString("utf8"),i=JSON.parse(n);if(i&&typeof i=="object"&&i.alg)return{isValid:!0,confidenceBonus:15,reason:`Valid JWT structure with signature algorithm: ${i.alg}`}}catch{}return{isValid:!1,confidenceBonus:0,reason:"Malformed JWT header JSON payload"}}function st(t){try{let e=new URL(t);if(!["postgres:","postgresql:","mysql:","mongodb:","mongodb+srv:","redis:"].includes(e.protocol))return{isValid:!1,confidenceBonus:0,reason:"Unsupported database protocol scheme"};if(e.password&&e.password.length>0)return{isValid:!0,confidenceBonus:12,reason:`Database connection string containing credentials for user '${e.username||"default"}'`}}catch{let e=/^(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis):\/\/[^:\s'"]+:([^\s'"]+)@([a-zA-Z0-9_.-]+(?::[0-9]+)?\/[^\s'"`;]*)/i,n=t.match(e);if(n&&n[1])return{isValid:!0,confidenceBonus:10,reason:"Database connection URI structure matched with embedded password"}}return{isValid:!1,confidenceBonus:0,reason:"Invalid database connection URL structure"}}function ot(t){return/^sk-proj-[A-Za-z0-9_-]{48,}$/.test(t)?{isValid:!0,confidenceBonus:15,reason:"Valid OpenAI Project API Key format"}:/^sk-admin-[A-Za-z0-9_-]{48,}$/.test(t)?{isValid:!0,confidenceBonus:15,reason:"Valid OpenAI Admin/Organization API Key format"}:/^sk-svcacct-[A-Za-z0-9_-]{48,}$/.test(t)?{isValid:!0,confidenceBonus:15,reason:"Valid OpenAI Service Account Key format"}:/^sk-[A-Za-z0-9]{32,48}$/.test(t)?{isValid:!0,confidenceBonus:10,reason:"Valid OpenAI Standard/Legacy API Key format"}:{isValid:!1,confidenceBonus:0,reason:"Invalid OpenAI API key structure"}}function rt(t){return/^sk-ant-[A-Za-z0-9_-]{40,}$/.test(t)?{isValid:!0,confidenceBonus:15,reason:"Valid Anthropic Claude API Key format"}:{isValid:!1,confidenceBonus:0,reason:"Invalid Anthropic API key format"}}function at(t){return/^AIza[0-9A-Za-z_-]{35}$/.test(t)?{isValid:!0,confidenceBonus:12,reason:"Valid Google Cloud / Gemini AIza service key signature"}:{isValid:!1,confidenceBonus:0,reason:"Invalid Google Cloud API key format"}}function ct(t){return/^xox[baprs]-[0-9A-Za-z-]{10,72}$/.test(t)?{isValid:!0,confidenceBonus:12,reason:`Valid Slack ${t.startsWith("xoxb")?"Bot Token":t.startsWith("xoxp")?"User Token":"OAuth Token"} signature`}:{isValid:!1,confidenceBonus:0,reason:"Invalid Slack token structure"}}function dt(t){return/^hf_[A-Za-z0-9]{34}$/.test(t)?{isValid:!0,confidenceBonus:12,reason:"Valid Hugging Face User Access Token format"}:{isValid:!1,confidenceBonus:0,reason:"Invalid Hugging Face token structure"}}function lt(t){return/^[A-Za-z0-9/+=]{40}$/.test(t)?{isValid:!0,confidenceBonus:12,reason:"Valid 40-character AWS Secret Access Key Base64 format"}:{isValid:!1,confidenceBonus:0,reason:"Invalid AWS Secret Access Key format"}}function pt(t){return/^https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9_]{8,12}\/B[A-Z0-9_]{8,12}\/[A-Za-z0-9_]{24}$/.test(t)?{isValid:!0,confidenceBonus:15,reason:"Valid Slack Incoming Webhook URL structure"}:{isValid:!1,confidenceBonus:0,reason:"Invalid Slack Incoming Webhook URL"}}function ut(t){return/^[A-Za-z0-9/+=]{86,88}==$/.test(t)?{isValid:!0,confidenceBonus:12,reason:"Valid Azure Storage Account Key Base64 format with padding"}:{isValid:!1,confidenceBonus:0,reason:"Invalid Azure Storage Key format"}}function gt(t){let e=/-----BEGIN (?:[A-Z0-9_-]+ )*PRIVATE KEY(?: BLOCK)?-----/.test(t),n=/-----END (?:[A-Z0-9_-]+ )*PRIVATE KEY(?: BLOCK)?-----/.test(t);return e&&n?{isValid:!0,confidenceBonus:20,reason:"Valid Cryptographic Private Key PEM block container"}:{isValid:!1,confidenceBonus:0,reason:"Incomplete or malformed PEM key container"}}function Oe(t,e,n,i,s,a){let o=[],r=t.baseConfidence;o.push({signal:"KNOWN_PATTERN_MATCH",description:`Matched recognized credential signature for ${t.provider} (${t.name})`,confidenceImpact:0,details:{ruleId:t.id,provider:t.provider}});let l=de(e),d=Xe(e),{setName:g}=Ne(e);if(t.minEntropy&&l<t.minEntropy?(r=Math.max(10,r-30),o.push({signal:"LOW_ENTROPY",description:`Low entropy score: ${l} bits/char below minimum threshold of ${t.minEntropy}`,confidenceImpact:-30,details:{shannonEntropy:l,minEntropy:t.minEntropy}})):l>=4.5?(r=Math.min(100,r+5),o.push({signal:"HIGH_ENTROPY",description:`Cryptographic entropy: ${l} bits/char (${g} set), indicates non-human randomness`,confidenceImpact:5,details:{shannonEntropy:l,normalizedEntropy:d,characterSet:g}})):l>=3.4?o.push({signal:"MODERATE_ENTROPY",description:`Moderate entropy: ${l} bits/char (${g} set)`,confidenceImpact:0,details:{shannonEntropy:l,normalizedEntropy:d,characterSet:g}}):(r=Math.max(10,r-15),o.push({signal:"LOW_ENTROPY",description:`Low entropy score: ${l} bits/char (${g} set)`,confidenceImpact:-15,details:{shannonEntropy:l,normalizedEntropy:d,characterSet:g}})),i.isSensitiveIdentifier||a?.isSensitiveProperty){let h=a?.variablePath||i.inferredVariable||"credential";r=Math.min(100,r+10),o.push({signal:"SENSITIVE_IDENTIFIER",description:`Assigned to sensitive identifier / property: '${h}'`,confidenceImpact:10,details:{identifier:h}})}else i.isBenignIdentifier&&(r=Math.max(10,r-25),o.push({signal:"BENIGN_IDENTIFIER",description:`Identifier name indicates mock or sample value: '${i.inferredVariable}'`,confidenceImpact:-25,details:{identifier:i.inferredVariable}}));a?.isEnvFallback&&(r=Math.min(100,r+12),o.push({signal:"ENV_FALLBACK_ASSIGNMENT",description:'Hardcoded literal provided as environment variable fallback (e.g. process.env.KEY || "...")',confidenceImpact:12})),a?.isAuthorizationHeader&&(r=Math.min(100,r+10),o.push({signal:"AUTHORIZATION_HEADER",description:"Passed in HTTP Authorization or Bearer token header context",confidenceImpact:10})),(n.isConfig||n.isSensitiveName)&&(r=Math.min(100,r+8),o.push({signal:"PRODUCTION_CONFIG_FILE",description:`Located in configuration or secret storage file (${n.fileExtension})`,confidenceImpact:8,details:{isConfig:n.isConfig,extension:n.fileExtension}})),n.isTest&&(r=Math.max(20,r-20),o.push({signal:"TEST_FILE_PENALTY",description:"Found inside test/mock directory structure",confidenceImpact:-20})),n.isDoc&&(r=Math.max(20,r-25),o.push({signal:"DOCUMENTATION_PENALTY",description:"Found inside documentation or markdown guide",confidenceImpact:-25}));let c;t.id==="aws-access-key"?c=et(e):t.id==="aws-secret-key"?c=lt(e):t.id==="stripe-secret-key"?c=tt(e):t.id==="github-pat"?c=nt(e):t.id==="jwt-token"?c=it(e):t.id==="database-url"?c=st(e):t.id==="openai-api-key"?c=ot(e):t.id==="anthropic-api-key"?c=rt(e):t.id==="google-api-key"?c=at(e):t.id==="slack-bot-token"?c=ct(e):t.id==="slack-webhook"?c=pt(e):t.id==="azure-storage-key"?c=ut(e):t.id==="huggingface-token"?c=dt(e):t.id==="private-key"&&(c=gt(e)),c&&c.isValid&&(r=Math.min(100,r+c.confidenceBonus),o.push({signal:"STRUCTURAL_VALIDATION_PASSED",description:`Structural validation verified: ${c.reason}`,confidenceImpact:c.confidenceBonus}));let p=Qe(e,i.inferredVariable,s);if(p.isFalsePositive)return{confidence:0,evidence:{items:[{signal:"KNOWN_PLACEHOLDER_REJECTED",description:p.reason||"Placeholder value rejected",confidenceImpact:-100}],shannonEntropy:l,normalizedEntropy:d,characterSet:g,surroundingCode:{before:i.surroundingBefore,targetLine:i.matchedLine,after:i.surroundingAfter,inferredVariable:i.inferredVariable},fileContext:{fileExtension:n.fileExtension,isConfig:n.isConfig,isTest:n.isTest,isDoc:n.isDoc,isSensitiveName:n.isSensitiveName,isExampleOrSample:n.isExampleOrSample}},isSuppressed:!0,suppressReason:p.reason};p.confidencePenalty>0&&(r=Math.max(10,r-p.confidencePenalty));let u=Math.max(0,Math.min(100,Math.round(r))),m={items:o,shannonEntropy:l,normalizedEntropy:d,characterSet:g,surroundingCode:{before:i.surroundingBefore,targetLine:i.matchedLine,after:i.surroundingAfter,inferredVariable:i.inferredVariable},fileContext:{fileExtension:n.fileExtension,isConfig:n.isConfig,isTest:n.isTest,isDoc:n.isDoc,isSensitiveName:n.isSensitiveName,isExampleOrSample:n.isExampleOrSample}};return{confidence:u,evidence:m,isSuppressed:!1}}function Me(t,e,n,i){let s=[],a=0,o=Math.min(40,Math.round(t.baseRiskWeight/100*40));a+=o,s.push({factor:"CREDENTIAL_SEVERITY",weight:40,scoreContribution:o,explanation:`${t.provider} ${t.name} has high inherent privilege capability`});let r=Math.round(e/100*25);a+=r,s.push({factor:"CONFIDENCE_LEVEL",weight:25,scoreContribution:r,explanation:`Multi-signal verification confidence is ${e}%`});let l=5,d="Standard source code file";n.isConfig||n.isSensitiveName?(l=15,d="Located in sensitive deployment / environment configuration"):n.isTest?(l=0,d="Located in test / fixture codebase with reduced operational blast radius"):n.isDoc&&(l=0,d="Located in documentation context"),a+=l,s.push({factor:"STORAGE_ENVIRONMENT",weight:15,scoreContribution:l,explanation:d});let g=5,c="Found in local uncommitted working tree";i&&(i.isRemote?(g=20,c="Pushed to remote repository branch (external exposure risk)"):i.isPresentInHistory?(g=16,c=`Committed to Git history across ${i.branches.length||1} branch(es) (${i.exposureDurationDays} days exposure)`):i.isPresentInHead&&(g=12,c="Committed in current HEAD commit")),a+=g,s.push({factor:"EXPOSURE_REACH",weight:20,scoreContribution:g,explanation:c});let p=Math.max(0,Math.min(100,Math.round(a))),u="LOW";p>=76?u="CRITICAL":p>=51?u="HIGH":p>=26?u="MEDIUM":u="LOW";let m=jt(p,i),h=`${u} Risk (${p}/100) \u2014 ${t.name}. ${m.summary}`;return{score:p,tier:u,factors:s,blastRadius:m,summary:h}}function jt(t,e){let n=[],i=Math.round(t*.5),s=e?e.isPresentInHead:!0,a=e?e.isPresentInHistory:!1,o=e?.isPresentInHistory?1:0,r=e?.branches||["main"],l=r.length,d=e?.isRemote||!1,g=e?.exposureDurationDays||0;s&&(n.push("Active working tree contains exposed secret"),i+=15),a&&(n.push(`Git history contains commit records across ${l} branch(es)`),i+=20),d&&(n.push("Secret has been synchronized to remote tracking branches"),i+=25),g>7&&(n.push(`Exposure duration exceeds ${g} days without rotation`),i+=10),i=Math.max(0,Math.min(100,i));let c="CONTAINED";i>=75?c="SEVERE":i>=50?c="EXTENSIVE":i>=25?c="MODERATE":c="CONTAINED";let p=`Blast Radius: ${c} (${i}/100) \u2014 ${d?"Remote & history exposure":a?"Historical commit exposure":"Contained to local working tree"}`;return{level:c,score:i,workingTreeExposed:s,gitHistoryExposed:a,commitCount:o,branchCount:l,branches:r,remoteExposed:d,exposureDurationDays:g,summary:p,factors:n}}var V=_(require("fs")),Z=_(require("path"));var mt=_(require("crypto")),Zt="sld_fingerprint_salt_v1_d8e9f2a1b4c3e7f0";function le(t){if(!t)return"";let e=t.length;if(e<=12)return"\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022";let n=Math.max(2,Math.floor(e*.2)),i=Math.min(4,Math.max(1,Math.floor(n/2))),s=Math.min(3,Math.max(1,n-i)),a=Math.max(6,Math.min(16,e-i-s)),o=t.substring(0,i),r=t.substring(e-s),l="\u2022".repeat(a);return`${o}${l}${r}`}function Be(t){return mt.createHmac("sha256",Zt).update(t).digest("hex").substring(0,16)}function We(t){return t.replace(/\\/g,"\\\\").replace(/"/g,'\\"').replace(/\$/g,"\\$").replace(/\n/g,"\\n").replace(/\r/g,"\\r")}function ft(t,e){switch(Z.extname(t).toLowerCase()){case".py":return`os.environ.get("${e}")`;case".go":return`os.Getenv("${e}")`;case".rb":return`ENV['${e}']`;case".php":return`getenv('${e}')`;case".java":case".kt":return`System.getenv("${e}")`;case".rs":return`std::env::var("${e}").unwrap()`;case".sh":case".bash":case".zsh":return`"\${${e}}"`;case".yaml":case".yml":case".toml":case".env":return`\${${e}}`;case".js":case".jsx":case".ts":case".tsx":case".mjs":case".cjs":default:return`process.env.${e}`}}function ze(t,e,n,i,s){let a=t.suggestedEnvName(s),o=ft(n,a),r=le(e),l=We(e),d=[`1. Revoke / rotate credential immediately with provider: ${t.provider}`,`2. Migrate secret value to local .env file (${a})`,`3. Replace hardcoded literal in ${n} with ${o}`,"4. Verify .env is listed in .gitignore so it is never committed","5. If committed previously, purge from Git history using git-filter-repo or BFG","6. Rescan file and commit to verify exposure is eliminated"],g=`${a}="${l}"`,c=`${a}=your_${a.toLowerCase()}_here`,p=`# WARNING: Use BFG Repo Cleaner to purge secrets from history (safer than filter-repo --invert-paths):
#   java -jar bfg.jar --replace-text secrets.txt <repo-dir>
# Where secrets.txt lists the exact literal to redact (one per line).
# Then force-push: git push --force --all && git push --force --tags
# Alternatively with git-filter-repo (rewrites content, not paths):
#   git filter-repo --replace-text secrets.txt`,u=`--- a/${n}
+++ b/${n}
@@ -${i},1 +${i},1 @@
- ... "${r}" ...
+ ... ${o} ...`;return{steps:d,envVarName:a,replacementCode:o,envFileSnippet:g,envExampleSnippet:c,gitHistoryPurgeCommand:p,diffPreview:u}}function Yt(t,e,n){let i=t.split(/\r?\n/),s=new Map;for(let a of i){let o=a.trim();if(!o||o.startsWith("#"))continue;let r=o.indexOf("=");if(r!==-1){let l=o.substring(0,r).trim(),d=o.substring(r+1).trim();(d.startsWith('"')&&d.endsWith('"')||d.startsWith("'")&&d.endsWith("'"))&&(d=d.substring(1,d.length-1)),s.set(l,d)}}if(s.has(e)){let a=s.get(e);if(a===We(n)||a===n)return{varName:e,isReused:!0};let o=2;for(;s.has(`${e}_${o}`);){if(s.get(`${e}_${o}`)===n)return{varName:`${e}_${o}`,isReused:!0};o++}return{varName:`${e}_${o}`,isReused:!1}}return{varName:e,isReused:!1}}function qt(t){let e=Z.join(t,".gitignore");if(V.existsSync(e)){let n=V.readFileSync(e,"utf8");if(!n.split(/\r?\n/).some(a=>/^\s*\.env(?:\s|$)/.test(a))){let a=n.endsWith(`
`)||n.length===0?"":`
`;V.appendFileSync(e,`${a}# Credentials
.env
.env.*.local
`,"utf8")}}else V.writeFileSync(e,`# Credentials
.env
.env.*.local
`,"utf8");try{let{execFileSync:n}=require("child_process");try{n("git",["rev-parse","--is-inside-work-tree"],{cwd:t,stdio:"ignore"})}catch{return}try{throw n("git",["ls-files","--error-unmatch",".env"],{cwd:t,stdio:"ignore"}),new Error('.env is already tracked in Git index. Run "git rm --cached .env" to untrack it before storing secrets.')}catch(i){if(i.message&&i.message.includes("already tracked in Git index"))throw i}try{n("git",["check-ignore","-q",".env"],{cwd:t,stdio:"ignore"})}catch{throw new Error(".env is not ignored by Git according to git check-ignore.")}}catch(n){if(n.message&&(n.message.includes("already tracked")||n.message.includes("not ignored by Git")))throw n}}function ht(t,e,n=V){let i=t.fullPath,s=null,a=null,o=null,r=null,l=!1,d=!1,g=!1,c=Z.join(e,".env"),p=Z.join(e,".gitignore");try{if(!n.existsSync(i))return{success:!1,message:`Target file not found: ${i}`,envPath:"",modifiedFile:i};if(s=n.readFileSync(i,"utf8"),!s.includes(t.rawSecret))return{success:!1,message:"Secret no longer found in target file (may have already been modified).",envPath:"",modifiedFile:i};let u="";if(n.existsSync(c))a=n.readFileSync(c,"utf8"),u=a;else{l=!0;try{n.writeFileSync(c,"",{mode:384,encoding:"utf8"})}catch{}}n.existsSync(p)?o=n.readFileSync(p,"utf8"):d=!0;let m=t.remediation?.envVarName||"API_KEY",{varName:h,isReused:v}=Yt(u,m,t.rawSecret),P=ft(i,h),S=We(t.rawSecret),x=`${h}="${S}"
`;if(qt(e),!v){let R=u.endsWith(`
`)||u.length===0?"":`
`;n.appendFileSync(c,`${R}${x}`,"utf8");try{n.chmodSync(c,384)}catch{}}let F=Z.join(e,".env.example"),N=`${h}=your_${h.toLowerCase()}_here
`,Y=n.existsSync(F);if(Y?r=n.readFileSync(F,"utf8"):g=!0,!Y||!n.readFileSync(F,"utf8").includes(h)){let R=Y?n.readFileSync(F,"utf8"):"",w=R.endsWith(`
`)||R.length===0?"":`
`;n.appendFileSync(F,`${w}${N}`,"utf8")}let C=s,y=`"${t.rawSecret}"`,b=`'${t.rawSecret}'`,I=`\`${t.rawSecret}\``;return C.includes(y)?C=C.replace(new RegExp(xe(y),"g"),P):C.includes(b)?C=C.replace(new RegExp(xe(b),"g"),P):C.includes(I)?C=C.replace(new RegExp(xe(I),"g"),P):C=C.replace(new RegExp(xe(t.rawSecret),"g"),P),n.writeFileSync(i,C,"utf8"),{success:!0,message:`Successfully migrated ${t.type} to .env (${h}) and replaced in ${t.file}.`,envPath:c,modifiedFile:i}}catch(u){let m=[],h=(S,x)=>{let F=`${S}.sld-tmp-${Date.now()}`;n.writeFileSync(F,x,"utf8"),n.renameSync(F,S)};if(s!==null)try{h(i,s),n.readFileSync(i,"utf8")!==s&&m.push(`source file restored with mismatched content (${i})`)}catch(S){m.push(`source file restore failed (${i}): ${S.message}`)}if(l&&n.existsSync(c))try{n.unlinkSync(c),n.existsSync(c)&&m.push(".env delete did not take effect")}catch(S){m.push(`.env delete failed: ${S.message}`)}else if(a!==null&&n.existsSync(c))try{h(c,a)}catch(S){m.push(`.env restore failed: ${S.message}`)}if(d&&n.existsSync(p))try{n.unlinkSync(p),n.existsSync(p)&&m.push(".gitignore delete did not take effect")}catch(S){m.push(`.gitignore delete failed: ${S.message}`)}else if(o!==null&&n.existsSync(p))try{h(p,o)}catch(S){m.push(`.gitignore restore failed: ${S.message}`)}let v=Z.join(e,".env.example");if(g&&n.existsSync(v))try{n.unlinkSync(v),n.existsSync(v)&&m.push(".env.example delete did not take effect")}catch(S){m.push(`.env.example delete failed: ${S.message}`)}else if(r!==null&&n.existsSync(v))try{h(v,r)}catch(S){m.push(`.env.example restore failed: ${S.message}`)}let P=m.length===0?"Rollback completed successfully.":`ROLLBACK INCOMPLETE \u2014 manual inspection required: ${m.join("; ")}`;return{success:!1,message:`Remediation failed: ${u.message}. ${P}`,envPath:"",modifiedFile:t.fullPath}}}function xe(t){return t.replace(/[.*+?^${}()|[\]\\]/g,"\\$&")}function vt(t){return yt.createHash("sha256").update(t.replace(/\\/g,"/")).digest("hex").slice(0,8)}function Jt(t,e=4e3){if(t.length<e)return t;let n=!1,i=-1;for(let o=0;o<t.length;o++)if(t.charCodeAt(o)===10){if(o-i>e){n=!0;break}i=o}if(!n&&t.length-i<=e)return t;let s=t.split(/\r?\n/),a=[];for(let o of s)if(o.length<=e)a.push(o);else for(let r=0;r<o.length;r+=e-100)a.push(o.substring(r,r+e));return a.join(`
`)}function bt(t,e){return/(?:\/\/|#|\/\*|--)\s*(?:sld-ignore|secret-leak-ignore)/i.test(t)?!0:/^\s*(?:\/\/|#|\/\*|--)\s*(?:sld-ignore|secret-leak-ignore)(?:\s*\*\/)?\s*$/i.test(e)}function Q(t,e,n={}){let i=typeof n=="string"?{workspaceRoot:n}:n,s=Jt(t),a=i.rules||Ye,o=i.workspaceRoot,r=qe(e,o),l=s.split(/\r?\n/),d=[],g=null;function c(){if(!g){g=[0];for(let y=0;y<s.length;y++)s.charCodeAt(y)===10&&g.push(y+1)}return g}function p(y){let b=c(),I=0,R=b.length-1;for(;I<=R;){let w=I+R>>1;if(b[w]<=y){if(w===b.length-1||b[w+1]>y)return{line:w+1,column:y-b[w]+1};I=w+1}else R=w-1}return{line:1,column:y+1}}let u=null;function m(y){if(s.length<=1024*1024)return u||(u=s.split(/\r?\n/)),{lines:u,relativeTargetIdx:y-1};let b=c(),I=y-1,R=Math.max(0,I-30),w=Math.min(b.length-1,I+30),O=b[R],j=w+1<b.length?b[w+1]:s.length;return{lines:s.substring(O,j).split(/\r?\n/),relativeTargetIdx:I-R}}for(let y of a){y.pattern.lastIndex=0;let b;for(;(b=y.pattern.exec(s))!==null;){let I=b[1]!==void 0?b[1]:b[0],R=b[1]!==void 0?b[0].indexOf(b[1]):0,w=b.index+(R>=0?R:0),{line:O,column:j}=p(w),ne=l[O-1]||"",W=O>1?l[O-2]:"";if(bt(ne,W))continue;let q=m(O),ve=Le(q.lines,q.relativeTargetIdx),z=$e(q.lines,q.relativeTargetIdx,e),M=Oe(y,I,r,ve,e,z);if(M.isSuppressed)continue;let G;if(y.minEntropy!==void 0&&(y.provider==="Generic"&&i.minEntropyThreshold!==void 0?G=i.minEntropyThreshold:G=y.minEntropy),G!==void 0&&M.evidence.shannonEntropy<G)continue;let J=e;if(o){let ce=ie.relative(o,e);!ce.startsWith("..")&&!ie.isAbsolute(ce)&&(J=ce)}let ae=Me(y,M.confidence,r),be=ze(y,I,J,O,ve.inferredVariable),ye=vt(J),ke=Be(I),De=`sec_${ke}_${ye}`,X=le(I),Pt={id:De,fingerprint:ke,type:y.name,provider:y.provider,file:J,fullPath:e,line:O,column:j,length:I.length,rawSecret:I,redactedSecret:X,confidence:M.confidence,risk:ae.tier,riskAssessment:ae,evidence:M.evidence,remediation:be,status:"ACTIVE",detectedAt:new Date().toISOString(),signals:M.evidence.items.map(ce=>ce.description),exampleFix:be.replacementCode,entropy:M.evidence.shannonEntropy};d.push(Pt)}}let h=[],v=/["']([^"'\r\n]{2,80})["']\s*\+\s*["']([^"'\r\n]{8,120})["']/g,P;for(;(P=v.exec(s))!==null;)h.push({combined:P[1]+P[2],matchOffset:P.index,matchLength:P[0].length,description:"Resolved split string concatenation"});let S=/\[\s*["']([^"'\r\n]{2,80})["']\s*,\s*["']([^"'\r\n]{8,120})["'](?:\s*,\s*["']([^"'\r\n]{2,120})["'])*\s*\]\s*\.\s*join\s*\(\s*["']\s*["']\s*\)/g,x;for(;(x=S.exec(s))!==null;){let y=[x[1],x[2],x[3]].filter(Boolean);h.push({combined:y.join(""),matchOffset:x.index,matchLength:x[0].length,description:"Resolved split array join expression"})}let F=/`([^`\r\n]{2,80})\$\{\s*["']([^"'\r\n]{8,120})["']\s*\}([^`\r\n]*?)`/g,N;for(;(N=F.exec(s))!==null;)h.push({combined:N[1]+N[2]+(N[3]||""),matchOffset:N.index,matchLength:N[0].length,description:"Resolved template literal interpolation"});let Y=/(?:Buffer\.from|atob|b64decode)\s*\(\s*(?:b)?["']([A-Za-z0-9+/=]{24,200})["']/g,C;for(;(C=Y.exec(s))!==null;)try{let y=Buffer.from(C[1],"base64").toString("utf8");y.length>=10&&/^[\x20-\x7E\r\n]+$/.test(y)&&h.push({combined:y,matchOffset:C.index,matchLength:C[0].length,description:"Resolved base64-encoded credential payload"})}catch{}for(let y of h)for(let b of a){b.pattern.lastIndex=0;let I;for(;(I=b.pattern.exec(y.combined))!==null;){let R=I[1]||I[0],{line:w,column:O}=p(y.matchOffset),j=l[w-1]||"",ne=w>1?l[w-2]:"";if(bt(j,ne))continue;let W=m(w),q=Le(W.lines,W.relativeTargetIdx),ve=$e(W.lines,W.relativeTargetIdx,e),z=Oe(b,R,r,q,e,ve);if(z.isSuppressed)continue;let M;if(b.minEntropy!==void 0&&(b.provider==="Generic"&&i.minEntropyThreshold!==void 0?M=i.minEntropyThreshold:M=b.minEntropy),M!==void 0&&z.evidence.shannonEntropy<M)continue;let G=e;if(o){let X=ie.relative(o,e);!X.startsWith("..")&&!ie.isAbsolute(X)&&(G=X)}let J=Me(b,z.confidence,r),ae=ze(b,R,G,w,q.inferredVariable);z.evidence.items.unshift({signal:"ADVERSARIAL_DEOBFUSCATION_RESOLVED",description:y.description,confidenceImpact:10});let be=vt(G),ye=Be(R),ke=`sec_${ye}_${be}`,De=le(R);d.push({id:ke,fingerprint:ye,type:b.name,provider:b.provider,file:G,fullPath:e,line:w,column:O,length:y.matchLength,rawSecret:R,redactedSecret:De,confidence:Math.min(100,z.confidence+5),risk:J.tier,riskAssessment:J,evidence:z.evidence,remediation:ae,status:"ACTIVE",detectedAt:new Date().toISOString(),signals:z.evidence.items.map(X=>X.description),exampleFix:ae.replacementCode,entropy:z.evidence.shannonEntropy})}}return Xt(d)}function Xt(t){let e=[];for(let n of t){let i=e.findIndex(s=>s.file===n.file&&s.line===n.line&&(s.rawSecret.includes(n.rawSecret)||n.rawSecret.includes(s.rawSecret)));if(i===-1)e.push(n);else{let s=e[i];(s.provider==="Generic Credential"&&n.provider!=="Generic Credential"||n.confidence>s.confidence)&&(e[i]=n)}}return e}var Ce=class{diagnosticCollection;currentFindings=new Map;ignoredFindings=new Set;onFindingsChangedEmitter=new E.EventEmitter;onFindingsChanged=this.onFindingsChangedEmitter.event;minEntropy;constructor(){this.diagnosticCollection=E.languages.createDiagnosticCollection("secret-leak-detector")}setMinEntropy(e){this.minEntropy=e}getDiagnosticCollection(){return this.diagnosticCollection}getAllFindings(){let e=[];for(let n of this.currentFindings.values())e.push(...n);return e}clear(){this.diagnosticCollection.clear(),this.currentFindings.clear(),this.onFindingsChangedEmitter.fire([])}ignoreFinding(e){this.ignoredFindings.add(e);for(let[n,i]of this.currentFindings.entries()){let s=i.filter(a=>a.id!==e);if(s.length!==i.length){this.currentFindings.set(n,s);let a=E.Uri.file(n),o=this.diagnosticCollection.get(a);if(o){let r=o.filter(l=>(typeof l.code=="object"?l.code?.value:l.code)!==e);this.diagnosticCollection.set(a,r)}}}this.onFindingsChangedEmitter.fire(this.getAllFindings())}setIgnoredFindings(e){this.ignoredFindings=new Set(e)}getIgnoredFindings(){return Array.from(this.ignoredFindings)}scanDocument(e){if(e.uri.scheme!=="file")return[];let n=e.getText();if(n.length>5*1024*1024)return[];let i=E.workspace.getWorkspaceFolder(e.uri),a={workspaceRoot:i?i.uri.fsPath:void 0,minEntropyThreshold:this.minEntropy},r=Q(n,e.uri.fsPath,a).filter(d=>!this.ignoredFindings.has(d.id));this.currentFindings.set(e.uri.fsPath,r);let l=[];for(let d of r){let g=Math.max(0,d.line-1),c=Math.max(0,d.column-1),p=new E.Position(g,c),u=e.offsetAt(p),m=e.positionAt(u+d.length),h=new E.Range(p,m),v=E.DiagnosticSeverity.Warning;d.risk==="CRITICAL"||d.risk==="HIGH"?v=E.DiagnosticSeverity.Error:d.risk==="LOW"&&(v=E.DiagnosticSeverity.Information);let P=typeof d.remediation=="string"?d.remediation:d.remediation?.steps?.[0]||"Migrate to .env",S=new E.Diagnostic(h,`[Secret Leak Detector] ${d.type} detected! Confidence: ${d.confidence}%. ${P}`,v);S.code={value:d.id,target:E.Uri.parse("https://github.com/MokuLakshithReddy/Secret_Leak_Detector")},S.source="Secret Leak Detector",l.push(S)}return this.diagnosticCollection.set(e.uri,l),this.onFindingsChangedEmitter.fire(this.getAllFindings()),r}toDiagnostic(e){let n=Math.max(0,e.line-1),i=Math.max(0,e.column-1),s=new E.Position(n,i),a=new E.Position(n,i+e.length),o=new E.Range(s,a),r=E.DiagnosticSeverity.Warning;e.risk==="CRITICAL"||e.risk==="HIGH"?r=E.DiagnosticSeverity.Error:e.risk==="LOW"&&(r=E.DiagnosticSeverity.Information);let l=typeof e.remediation=="string"?e.remediation:e.remediation?.steps?.[0]||"Migrate to .env",d=new E.Diagnostic(o,`[Secret Leak Detector] ${e.type} detected! Confidence: ${e.confidence}%. ${l}`,r);return d.code={value:e.id,target:E.Uri.parse("https://github.com/MokuLakshithReddy/Secret_Leak_Detector")},d.source="Secret Leak Detector",d}setBatchFindings(e){this.diagnosticCollection.clear(),this.currentFindings.clear();for(let[n,i]of e.entries()){let s=i.filter(a=>!this.ignoredFindings.has(a.id));if(this.currentFindings.set(n,s),s.length>0){let a=E.Uri.file(n),o=s.map(r=>this.toDiagnostic(r));this.diagnosticCollection.set(a,o)}}this.onFindingsChangedEmitter.fire(this.getAllFindings())}renameDocument(e,n){let i=this.currentFindings.get(e.fsPath);if(this.removeDocument(e),i&&i.length>0){let s=i.map(o=>({...o,fullPath:n.fsPath,file:n.fsPath}));this.currentFindings.set(n.fsPath,s);let a=s.map(o=>this.toDiagnostic(o));this.diagnosticCollection.set(n,a),this.onFindingsChangedEmitter.fire(this.getAllFindings())}}removeDocument(e){this.diagnosticCollection.delete(e),this.currentFindings.delete(e.fsPath),this.onFindingsChangedEmitter.fire(this.getAllFindings())}dispose(){this.diagnosticCollection.dispose(),this.onFindingsChangedEmitter.dispose()}};var L=_(require("vscode"));var se=class{static providedCodeActionKinds=[L.CodeActionKind.QuickFix];diagnosticProvider;constructor(e){this.diagnosticProvider=e}provideCodeActions(e,n,i){let s=[],a=i.diagnostics.filter(r=>r.source==="Secret Leak Detector");if(a.length===0)return s;let o=this.diagnosticProvider.getAllFindings();for(let r of a){let l=typeof r.code=="object"?r.code?.value:r.code,d=o.find(u=>u.id===l);if(!d||e.getText(r.range)!==d.rawSecret)continue;let c=this.createMoveToEnvAction(e,r.range,d);s.push(c);let p=new L.CodeAction("Ignore this finding (False Positive)",L.CodeActionKind.QuickFix);p.command={command:"secret-leak-detector.ignoreFinding",title:"Ignore Finding",arguments:[d.id]},s.push(p)}return s}createMoveToEnvAction(e,n,i){let s=new L.CodeAction(`\u{1F6E1}\uFE0F Move ${i.type} to .env and replace with environment variable`,L.CodeActionKind.QuickFix);return s.isPreferred=!0,s.command={command:"secret-leak-detector.remediateFinding",title:"Move to .env",arguments:[e.uri,n,i]},s}static async executeRemediation(e,n,i){let s=L.workspace.getWorkspaceFolder(e);if(!s){L.window.showErrorMessage("No workspace folder found to save .env file.");return}let a=s.uri.fsPath;if((await L.workspace.openTextDocument(e)).getText(n)!==i.rawSecret){L.window.showErrorMessage("The secret at the target location has changed or was already removed.");return}let r=ht(i,a);if(!r.success){L.window.showErrorMessage(`Remediation aborted: ${r.message}`);return}L.window.showInformationMessage(`\u{1F6E1}\uFE0F ${r.message}`)}};var k=_(require("vscode")),Ie=class{_onDidChangeTreeData=new k.EventEmitter;onDidChangeTreeData=this._onDidChangeTreeData.event;findings=[];updateFindings(e){this.findings=e,this._onDidChangeTreeData.fire()}getTreeItem(e){return e}getChildren(e){if(!e){if(this.findings.length===0){let s=new H("No Leaks Detected (Safe)",k.TreeItemCollapsibleState.None);return s.iconPath=new k.ThemeIcon("shield-check",new k.ThemeColor("testing.iconPassed")),s.description="Workspace is clean",Promise.resolve([s])}let n=["CRITICAL","HIGH","MEDIUM","LOW"],i=[];for(let s of n){let a=this.findings.filter(o=>o.risk===s).length;if(a>0){let o=new H(`${s} Risk (${a})`,k.TreeItemCollapsibleState.Expanded,s);s==="CRITICAL"?o.iconPath=new k.ThemeIcon("error",new k.ThemeColor("errorForeground")):s==="HIGH"?o.iconPath=new k.ThemeIcon("warning",new k.ThemeColor("editorWarning.foreground")):s==="MEDIUM"?o.iconPath=new k.ThemeIcon("info",new k.ThemeColor("editorInfo.foreground")):o.iconPath=new k.ThemeIcon("pass",new k.ThemeColor("testing.iconPassed")),i.push(o)}}return Promise.resolve(i)}if(e.contextValue){let n=e.contextValue,i=this.findings.filter(o=>o.risk===n),s=k.workspace.getConfiguration("secretLeakDetector").get("redactSecrets",!0),a=i.map(o=>{let r=new H(`${o.type}`,k.TreeItemCollapsibleState.None),l=s?o.redactedSecret:o.rawSecret;return r.description=`${o.file}:${o.line}`,r.tooltip=new k.MarkdownString(`**${o.type}** (${o.provider})

- **Risk:** ${o.risk}
- **Confidence:** ${o.confidence}%
- **Entropy:** ${o.entropy} bits/char
- **Secret:** \`${l}\`

*Suggested Fix: ${o.remediation?.replacementCode||o.remediation?.envVarName||"Migrate to .env"}*`),r.iconPath=new k.ThemeIcon("key"),r.command={command:"vscode.open",title:"Jump to Secret",arguments:[k.Uri.file(o.fullPath),{selection:new k.Range(o.line-1,o.column-1,o.line-1,o.column-1+o.length)}]},r});return Promise.resolve(a)}return Promise.resolve([])}},we=class{_onDidChangeTreeData=new k.EventEmitter;onDidChangeTreeData=this._onDidChangeTreeData.event;findingsCount=0;isGit=!0;update(e,n){this.findingsCount=e,this.isGit=n,this._onDidChangeTreeData.fire()}getTreeItem(e){return e}getChildren(){let e=[],n=new H(this.findingsCount===0?"Status: Protected":`Status: ${this.findingsCount} Leaks Active`,k.TreeItemCollapsibleState.None);n.iconPath=new k.ThemeIcon(this.findingsCount===0?"check":"alert",this.findingsCount===0?new k.ThemeColor("testing.iconPassed"):new k.ThemeColor("errorForeground")),e.push(n);let i=new H("Run Full Workspace Scan",k.TreeItemCollapsibleState.None);i.iconPath=new k.ThemeIcon("search"),i.command={command:"secret-leak-detector.scanWorkspace",title:"Scan Workspace"},e.push(i);let s=new H("Check Git Staged Changes",k.TreeItemCollapsibleState.None);s.iconPath=new k.ThemeIcon("git-commit"),s.command={command:"secret-leak-detector.scanStaged",title:"Scan Staged Changes"},e.push(s);let a=new H("Open Interactive Dashboard",k.TreeItemCollapsibleState.None);a.iconPath=new k.ThemeIcon("dashboard"),a.command={command:"secret-leak-detector.openDashboard",title:"Open Dashboard"},e.push(a);let o=new H("Install Pre-Commit Hook",k.TreeItemCollapsibleState.None);return o.iconPath=new k.ThemeIcon("terminal"),o.command={command:"secret-leak-detector.installGitHook",title:"Install Hook"},e.push(o),Promise.resolve(e)}},H=class extends k.TreeItem{constructor(e,n,i){super(e,n),this.contextValue=i}};var D=_(require("vscode")),kt=_(require("crypto")),St=_(require("fs")),pe=_(require("path"));function Ke(t){let e=typeof t.remediation=="string"?t.remediation:t.remediation?.steps?.join("; ")||"Rotate and move to .env",n=t.exampleFix||t.remediation?.replacementCode||"";return{id:t.id,type:t.type,provider:t.provider,file:t.file,fullPath:t.fullPath,line:t.line,column:t.column,redactedSecret:t.redactedSecret,confidence:t.confidence,entropy:t.entropy??0,risk:t.risk,remediationText:e,exampleFix:n}}var ee=class t{static currentPanel;static viewType="secretLeakDetectorDashboard";_panel;_extensionUri;_disposables=[];_findings=[];static createOrShow(e,n){let i=D.window.activeTextEditor?D.window.activeTextEditor.viewColumn:void 0;if(t.currentPanel){t.currentPanel._panel.reveal(i),t.currentPanel.updateFindings(n);return}let s=D.window.createWebviewPanel(t.viewType,"\u{1F510} Secret Leak Detector Dashboard",i||D.ViewColumn.One,{enableScripts:!0,retainContextWhenHidden:!0,localResourceRoots:[e]});t.currentPanel=new t(s,e,n)}constructor(e,n,i){this._panel=e,this._extensionUri=n,this._findings=i,this._update(),this._panel.onDidDispose(()=>this.dispose(),null,this._disposables),this._panel.webview.onDidReceiveMessage(async s=>{switch(s.command){case"scanWorkspace":D.commands.executeCommand("secret-leak-detector.scanWorkspace");return;case"scanStaged":D.commands.executeCommand("secret-leak-detector.scanStaged");return;case"installHook":D.commands.executeCommand("secret-leak-detector.installGitHook");return;case"openFile":if(typeof s.file=="string"&&s.file.trim().length>0&&typeof s.line=="number"&&s.line>=1){let a=this._findings.find(r=>r.file===s.file||r.fullPath===s.file);if(!a)return;let o=a.fullPath;if(!pe.isAbsolute(o)){let r=D.workspace.workspaceFolders?.[0]?.uri.fsPath;o=r?pe.resolve(r,o):pe.resolve(o)}if(St.existsSync(o))try{let r=await D.workspace.openTextDocument(D.Uri.file(o));await D.window.showTextDocument(r,{selection:new D.Range(s.line-1,0,s.line-1,0)})}catch{}}return}},null,this._disposables)}updateFindings(e){this._findings=e;let n=this._findings.map(Ke);this._panel.webview.postMessage({command:"updateData",findings:n})}dispose(){for(t.currentPanel=void 0,this._panel.dispose();this._disposables.length;){let e=this._disposables.pop();e&&e.dispose()}}_update(){this._panel.webview.html=this._getHtmlForWebview()}_getHtmlForWebview(){let e=kt.randomBytes(16).toString("base64"),n=this._findings.map(Ke),i=JSON.stringify(n).replace(/</g,"\\u003c");return`<!DOCTYPE html>
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
</html>`}};var _t=require("child_process"),Tt=require("util"),A=_(require("fs")),T=_(require("path"));var te=require("child_process"),At=require("util"),re=_(require("path"));var Re=_(require("fs")),_e=_(require("path")),ue=new Set([".png",".jpg",".jpeg",".gif",".bmp",".ico",".webp",".tiff",".tif",".pdf",".zip",".tar",".gz",".bz2",".7z",".rar",".exe",".dll",".so",".dylib",".bin",".iso",".dmg",".woff",".woff2",".ttf",".eot",".otf",".mp3",".mp4",".avi",".mov",".wmv",".flv",".mkv",".pyc",".pyo",".class",".jar",".war",".sqlite",".db",".dat"]),He=["**/node_modules/**","**/.git/**","**/dist/**","**/build/**","**/*.min.js","**/*.lock","**/package-lock.json","**/pnpm-lock.yaml"];function Ge(t){let e=_e.join(t,".sldignore");if(process.env.CI)try{let{execFileSync:n}=require("child_process"),i=process.env.GITHUB_BASE_REF||process.env.CI_MERGE_REQUEST_TARGET_BRANCH_NAME,s=[...i?[`origin/${i}`,i,`refs/remotes/origin/${i}`]:[],"HEAD"];for(let a of s)try{let o=n("git",["show",`${a}:.sldignore`],{cwd:t,encoding:"utf8",stdio:["ignore","pipe","ignore"]});if(o)return o.split(/\r?\n/).map(r=>r.trim()).filter(r=>r.length>0&&!r.startsWith("#"))}catch{}}catch{}if(Re.existsSync(e))try{return Re.readFileSync(e,"utf8").split(/\r?\n/).map(i=>i.trim()).filter(i=>i.length>0&&!i.startsWith("#"))}catch{}return[]}function Ve(t,e){let n=t.replace(/\\/g,"/").replace(/^\/+/,""),i=e.trim().replace(/\\/g,"/");if(!i||i.startsWith("#"))return!1;if(i.endsWith("/")&&(i=i.slice(0,-1)),n===i||n.startsWith(i+"/"))return!0;if(i.includes("*")||i.includes("?"))if(i.includes("/")){let o="^"+i.replace(/[.+^${}()|[\]\\]/g,"\\$&").replace(/\*\*/g,".*").replace(/\*/g,"[^/]*").replace(/\?/g,"[^/]")+"$";return new RegExp(o).test(n)}else{let o=_e.basename(n),r="^"+i.replace(/[.+^${}()|[\]\\]/g,"\\$&").replace(/\*/g,".*").replace(/\?/g,".")+"$";return new RegExp(r).test(o)}let a=n.split("/");return i.includes("/")?!1:a.includes(i)}var Te=(0,At.promisify)(te.execFile),oe=["-c","core.quotepath=false","--literal-pathspecs"],Pe=5*1024*1024;function Qt(t){try{let e=(0,te.execFileSync)("git",["rev-parse","--show-toplevel"],{cwd:t,encoding:"utf8"}).trim();if(e)return re.resolve(e)}catch{}return t}async function en(t){try{let{stdout:e}=await Te("git",["rev-parse","--show-toplevel"],{cwd:t,encoding:"utf8"}),n=e.trim();if(n)return re.resolve(n)}catch{}return t}function Et(t){let e=new Map,n=new Set,i=t.split(/^diff --git /m);for(let s of i){if(!s.trim())continue;let r=s.split(/\r?\n/)[0].match(/a\/(.+)\s+b\/(.+)/);if(!r)continue;let l=r[2].trim().replace(/\\/g,"/");if(l==="/dev/null")continue;if(s.includes("Binary files")||s.includes("GIT binary patch")){n.add(l);continue}let d=new Set,g=/^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/gm,c;for(;(c=g.exec(s))!==null;){let u=parseInt(c[1],10),m=c[2]!==void 0?parseInt(c[2],10):1;for(let h=0;h<m;h++)d.add(u+h)}let p=s.includes("rename to ");d.size>0?e.set(l,d):p&&e.set(l,new Set([-1]))}return{filesWithAdditions:e,binaryFiles:n}}function xt(t){let e=Qt(t),n;try{n=(0,te.execFileSync)("git",[...oe,"diff","--cached","-U0"],{cwd:e,encoding:"utf8",maxBuffer:25*1024*1024})}catch(d){return{status:"ERROR",findings:[],error:`git diff --cached failed: ${d.message||String(d)}`}}let{filesWithAdditions:i,binaryFiles:s}=Et(n),a=[...He,...Ge(e)],o=[],r=[],l=0;for(let[d,g]of i.entries()){let c=re.extname(d).toLowerCase();if(a.some(v=>Ve(d,v)))continue;if(s.has(d)||ue.has(c)){r.push({path:d,reason:"Binary file skipped"});continue}let p=0;try{let v=(0,te.execFileSync)("git",[...oe,"cat-file","-s",`:${d}`],{cwd:e,encoding:"utf8"}).trim();p=parseInt(v,10)||0}catch{r.push({path:d,reason:"Could not inspect blob size"});continue}if(p>Pe){r.push({path:d,reason:`File size (${(p/(1024*1024)).toFixed(1)}MB) exceeds 5MB limit`});continue}let u;try{u=(0,te.execFileSync)("git",[...oe,"show",`:${d}`],{cwd:e,encoding:"utf8",maxBuffer:Pe+1024})}catch(v){r.push({path:d,reason:`Unreadable staged blob: ${v.message}`});continue}let m=Q(u,d,{workspaceRoot:e}),h=g.has(-1);for(let v of m)(h||g.has(v.line))&&o.push(v);l++}return o.length>0?{status:"FINDINGS",findings:o,skippedFiles:r,filesScanned:l}:{status:"CLEAN",findings:[],skippedFiles:r,filesScanned:l}}async function Ct(t){let e=await en(t),n;try{let{stdout:d}=await Te("git",[...oe,"diff","--cached","-U0"],{cwd:e,encoding:"utf8",maxBuffer:26214400});n=d}catch(d){return{status:"ERROR",findings:[],error:`git diff --cached failed: ${d.message||String(d)}`}}let{filesWithAdditions:i,binaryFiles:s}=Et(n),a=[...He,...Ge(e)],o=[],r=[],l=0;for(let[d,g]of i.entries()){let c=re.extname(d).toLowerCase();if(a.some(v=>Ve(d,v)))continue;if(s.has(d)||ue.has(c)){r.push({path:d,reason:"Binary file skipped"});continue}let p=0;try{let{stdout:v}=await Te("git",[...oe,"cat-file","-s",`:${d}`],{cwd:e,encoding:"utf8"});p=parseInt(v.trim(),10)||0}catch{r.push({path:d,reason:"Could not inspect blob size"});continue}if(p>Pe){r.push({path:d,reason:`File size (${(p/(1024*1024)).toFixed(1)}MB) exceeds 5MB limit`});continue}let u;try{let{stdout:v}=await Te("git",[...oe,"show",`:${d}`],{cwd:e,encoding:"utf8",maxBuffer:Pe+1024});u=v}catch(v){r.push({path:d,reason:`Unreadable staged blob: ${v.message}`});continue}let m=Q(u,d,{workspaceRoot:e}),h=g.has(-1);for(let v of m)(h||g.has(v.line))&&o.push(v);l++}return o.length>0?{status:"FINDINGS",findings:o,skippedFiles:r,filesScanned:l}:{status:"CLEAN",findings:[],skippedFiles:r,filesScanned:l}}var je=["LOW","MEDIUM","HIGH","CRITICAL"],Ue={LOW:1,MEDIUM:2,HIGH:3,CRITICAL:4},B="HIGH";function tn(t){return typeof t=="string"&&je.includes(t.toUpperCase())}function Fe(t,e=B){return tn(t)?t.toUpperCase():e}function It(t,e=B){return(Ue[t]||0)>=(Ue[e]||Ue.CRITICAL)}var ge="# [SLD_HOOK_MANAGED]";function wt(t=B,e,n,i=!0){let s=je.includes(t)?t:B,a=e?e.replace(/\\/g,"/"):"",o=a?a.replace(/'/g,"'\\''"):"",r=n?n.replace(/\\/g,"/"):"",l=r?r.replace(/'/g,"'\\''"):"",d=l?`# Resolved Node.js executable
if [ -x '${l}' ]; then
  NODE_CMD='${l}'
elif command -v node >/dev/null 2>&1; then
  NODE_CMD='node'
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
fi`,g=a?`# Scanner pinned to bundled CLI path
PINNED_CLI='${o}'
if [ -n "$PINNED_CLI" ] && [ -f "$PINNED_CLI" ]; then
  if [ -z "$NODE_CMD" ]; then
    echo ""
    echo "\u274C COMMIT BLOCKED: Node.js runtime not found on PATH (exit 127)."
    echo "   The pre-commit hook requires Node.js (>=18) to execute the scanner."
    echo "   Ensure 'node' is in your PATH or configure your Git client environment."
    exit 127
  fi
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

${d}

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
`}var Rt=(0,Tt.promisify)(_t.execFile);var me=class{workspaceRoot;cliPath;onWarn;constructor(e,n,i){if(this.workspaceRoot=e,typeof n=="function"?this.onWarn=n:n&&A.existsSync(n)?(this.cliPath=n,this.onWarn=i):this.onWarn=i,!this.cliPath)if(process.env.SLD_CLI_PATH&&A.existsSync(process.env.SLD_CLI_PATH))this.cliPath=process.env.SLD_CLI_PATH;else{let s=[T.resolve(__dirname,"cli.js"),T.resolve(__dirname,"../cli/index.js"),T.resolve(__dirname,"../../dist/cli.js")];this.cliPath=s.find(a=>A.existsSync(a))}}async isGitRepo(){try{return await Rt("git",["rev-parse","--is-inside-work-tree"],{cwd:this.workspaceRoot}),!0}catch{return!1}}async scanStagedChanges(){return Ct(this.workspaceRoot)}scanStagedChangesSync(){return xt(this.workspaceRoot)}formatTerminalBlockedMessage(e){let i=e.filter(l=>l.risk==="CRITICAL")[0]||e[0],s=typeof i.remediation=="string"?i.remediation:i.remediation?.steps?.join(`
`)||"Rotate and move to .env",a=i.evidence?.items?.map(l=>`  - [${l.confidenceImpact>=0?"+":""}${l.confidenceImpact}] ${l.description}`).join(`
`)||i.signals?.map(l=>`  - ${l}`).join(`
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
${a}

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
`}async resolveHooksDir(){try{let{stdout:e}=await Rt("git",["rev-parse","--git-path","hooks"],{cwd:this.workspaceRoot}),n=e.trim();return T.isAbsolute(n)?n:T.resolve(this.workspaceRoot,n)}catch{return T.join(this.workspaceRoot,".git","hooks")}}async installPreCommitHook(e,n,i=!0,s=B){if(!await this.isGitRepo())return{success:!1,message:"Workspace is not a Git repository."};let a=await this.resolveHooksDir();if(!A.existsSync(a))try{A.mkdirSync(a,{recursive:!0})}catch(u){return{success:!1,message:`Could not create hooks directory (${a}): ${u}`}}let o=T.join(a,"pre-commit"),r=Date.now(),l=T.join(a,`pre-commit.sld-backup.${r}`),d=T.join(a,"pre-commit.sld-backup.latest"),g=ge;if(A.existsSync(o))try{let u=A.readFileSync(o,"utf8");u.includes(g)||(A.writeFileSync(l,u,{mode:493}),A.writeFileSync(d,l,"utf8"))}catch(u){return{success:!1,message:`Could not backup existing hook: ${u}`}}let c=e||this.cliPath;if(!c||!A.existsSync(c))return{success:!1,message:`Cannot install pre-commit hook: bundled CLI binary not found at '${c||"undefined"}'. Installation aborted.`};if(/[\/\\](?:_npx|Temp|tmp)[\/\\]/i.test(c)){let u=`\u26A0\uFE0F Warning: Pre-commit hook is pinning a temporary/npx CLI path: '${c}'. This path may be deleted automatically by your system. Consider installing secret-leak-detector globally or locally.`;this.onWarn?this.onWarn(u):console.warn(u)}let p=wt(s,c,n,i);try{return A.writeFileSync(o,p,{mode:493}),{success:!0,message:`Pre-commit hook successfully installed to ${o}`}}catch(u){return{success:!1,message:`Failed to write hook file: ${u}`}}}async ensureHookIsPinned(e,n,i=!0,s=B){if(!e||!A.existsSync(e)||!await this.isGitRepo())return!1;let a=await this.resolveHooksDir(),o=T.join(a,"pre-commit");if(!A.existsSync(o))return!1;try{let r=A.readFileSync(o,"utf8");if(!r.includes(ge))return!1;let l=e.replace(/\\/g,"/");if(!r.includes(l))return(await this.installPreCommitHook(e,n,i,s)).success}catch{return!1}return!0}async uninstallPreCommitHook(){let e=await this.resolveHooksDir(),n=T.join(e,"pre-commit"),i=T.join(e,"pre-commit.sld-backup.latest");if(!A.existsSync(n))return{success:!0,message:"No pre-commit hook found to uninstall."};try{if(!A.readFileSync(n,"utf8").includes(ge))return{success:!1,message:"Existing pre-commit hook is not managed by Secret Leak Detector; refusing to delete user hook."};if(A.existsSync(i)){let a=A.readFileSync(i,"utf8").trim(),o=T.resolve(a),r=T.resolve(e),l=T.basename(o);if(T.dirname(o)===r&&/^pre-commit\.sld-backup\.\d+$/.test(l)&&A.existsSync(o))return A.copyFileSync(o,n),A.unlinkSync(o),A.unlinkSync(i),{success:!0,message:"Uninstalled SLD hook and restored original pre-commit hook."};try{A.unlinkSync(i)}catch{}}return A.unlinkSync(n),{success:!0,message:"Removed Secret Leak Detector pre-commit hook."}}catch(s){return{success:!1,message:`Failed to uninstall hook: ${s.message}`}}}};var $,fe=new Map;function nn(t){$=f.window.createOutputChannel("Secret Leak Detector"),t.subscriptions.push($),$.appendLine("\u{1F510} [Secret Leak Detector] Extension activated.");let e=new Ce;t.subscriptions.push(e),t.subscriptions.push(f.languages.registerCodeActionsProvider({scheme:"file"},new se(e),{providedCodeActionKinds:se.providedCodeActionKinds}));let n=new Ie,i=new we;t.subscriptions.push(f.window.registerTreeDataProvider("secret-leak-detector.findingsView",n)),t.subscriptions.push(f.window.registerTreeDataProvider("secret-leak-detector.overviewView",i));let s=f.workspace.workspaceFolders?.[0],a=s?s.uri.fsPath:process.cwd(),o=new me(a,c=>$.appendLine(c));e.onFindingsChanged(c=>{n.updateFindings(c),i.update(c.length,!0),ee.currentPanel&&ee.currentPanel.updateFindings(c)});let r=()=>f.workspace.getConfiguration("secretLeakDetector");function l(){let p=r().get("minEntropy");e.setMinEntropy(typeof p=="number"&&p>0?p:void 0);let u=t.workspaceState.get("ignoredFindings",[]);e.setIgnoredFindings(u)}l();let d=he.join(t.extensionPath,"dist","cli.js");try{let c=t.globalStorageUri.fsPath;U.existsSync(c)||U.mkdirSync(c,{recursive:!0});let p=he.join(c,"cli.js");U.existsSync(d)&&(U.copyFileSync(d,p),d=p)}catch{}async function g(c){let p=f.workspace.workspaceFolders||[],u=r().get("blockGitCommits",!0),m=Fe(r().get("failOn",B));for(let h of p){let v=new me(h.uri.fsPath,P=>$.appendLine(P));await v.isGitRepo()&&await v.ensureHookIsPinned(c,process.execPath,u).catch(()=>{})}}U.existsSync(d)&&g(d).catch(()=>{}),t.subscriptions.push(f.workspace.onDidChangeWorkspaceFolders(async()=>{U.existsSync(d)&&await g(d).catch(()=>{})})),t.subscriptions.push(f.workspace.onDidChangeConfiguration(c=>{c.affectsConfiguration("secretLeakDetector")&&(l(),f.window.activeTextEditor&&e.scanDocument(f.window.activeTextEditor.document))})),f.window.activeTextEditor&&e.scanDocument(f.window.activeTextEditor.document),t.subscriptions.push(f.workspace.onDidSaveTextDocument(c=>{r().get("enableRealtimeScanning",!0)&&e.scanDocument(c)})),t.subscriptions.push(f.workspace.onDidOpenTextDocument(c=>{r().get("enableRealtimeScanning",!0)&&e.scanDocument(c)})),t.subscriptions.push(f.workspace.onDidChangeTextDocument(c=>{if(!r().get("enableRealtimeScanning",!0))return;let p=c.document.uri.toString(),u=fe.get(p);u&&clearTimeout(u);let m=setTimeout(()=>{e.scanDocument(c.document),fe.delete(p)},350);fe.set(p,m)})),t.subscriptions.push(f.workspace.onDidDeleteFiles(c=>{c.files.forEach(p=>e.removeDocument(p))})),t.subscriptions.push(f.workspace.onDidRenameFiles(c=>{c.files.forEach(p=>e.renameDocument(p.oldUri,p.newUri))})),t.subscriptions.push(f.commands.registerCommand("secret-leak-detector.scanWorkspace",async()=>{await f.window.withProgress({location:f.ProgressLocation.Notification,title:"\u{1F510} Scanning workspace for secret leaks...",cancellable:!0},async(c,p)=>{let u=r().get("excludeGlobs",[]),m=u.length>0?`{${u.join(",")}}`:void 0,h=1e3,v=await f.workspace.findFiles("**/*",m,h),P=new Map,S=[],x=0,F=0,N=v.length;for(let y=0;y<N;y++){if(p.isCancellationRequested){f.window.showInformationMessage("Secret Leak Detector: Workspace scan was cancelled.");return}let b=v[y],I=he.extname(b.fsPath).toLowerCase();if(ue.has(I)){F++;continue}try{if((await f.workspace.fs.stat(b)).size>5*1024*1024){F++;continue}let w=await f.workspace.fs.readFile(b),O=Buffer.from(w).toString("utf8"),j=f.workspace.getWorkspaceFolder(b),ne={workspaceRoot:j?j.uri.fsPath:void 0,minEntropyThreshold:r().get("minEntropy")},W=Q(O,b.fsPath,ne);P.set(b.fsPath,W),S.push(...W),x++}catch{F++}c.report({message:`${x}/${N} files scanned`,increment:1/(N||1)*100})}e.setBatchFindings(P);let Y=v.length>=h,C=`Scanned ${x} files.`;if(Y&&(C+=` \u26A0\uFE0F Scan was capped at ${h} files.`),F>0&&(C+=` (${F} large or binary files skipped)`),x===0)f.window.showWarningMessage(`\u26A0\uFE0F Workspace scan complete: 0 files were scanned. ${C}`);else if(S.length===0)f.window.showInformationMessage(`\u2705 Scan complete: ${C} No secrets or credentials detected!`);else{let y=S.filter(b=>b.risk==="CRITICAL").length;f.window.showErrorMessage(`\u{1F6A8} Found ${S.length} leaked secret(s) (${y} Critical)! ${C}`,"Open Dashboard","View Findings").then(b=>{b==="Open Dashboard"?f.commands.executeCommand("secret-leak-detector.openDashboard"):b==="View Findings"&&f.commands.executeCommand("workbench.view.extension.secret-leak-detector-sidebar")})}})})),t.subscriptions.push(f.commands.registerCommand("secret-leak-detector.scanStaged",async()=>{$.clear(),$.appendLine("\u{1F510} [Secret Leak Detector] Scanning Git staged changes..."),$.show(!0);let c=r().get("blockGitCommits",!0),p=Fe(r().get("failOn",B)),u=await o.scanStagedChanges();if(u.status==="ERROR"){$.appendLine(`\u274C [Secret Leak Detector] Scan error: ${u.error}`);let x=c?`\u274C COMMIT GATE BLOCKED: Git security scan failed (${u.error}). Failing closed for safety.`:`\u26A0\uFE0F Git scan encountered an error: ${u.error}`;f.window.showErrorMessage(x,"View Output").then(F=>{F==="View Output"&&$.show(!0)});return}if(u.skippedFiles&&u.skippedFiles.length>0){$.appendLine(`\u2139\uFE0F  Skipped ${u.skippedFiles.length} binary or oversized file(s):`);for(let x of u.skippedFiles)$.appendLine(`   \u2022 ${x.path}: ${x.reason}`)}if(u.status==="CLEAN"){$.appendLine("\u2705 All staged changes are clean! No credentials detected."),f.window.showInformationMessage("\u2705 Git staged changes are safe to commit.");return}let m=u.findings,h=m.filter(x=>It(x.risk,p)),v=o.formatTerminalBlockedMessage(h.length>0?h:m);$.appendLine(v);let S=c&&h.length>0?`\u274C COMMIT BLOCKED: ${h.length} secret(s) at or above ${p} detected in staged changes!`:`\u26A0\uFE0F WARNING: ${m.length} secret(s) detected in staged changes (none block at the ${p} threshold).`;f.window.showErrorMessage(S,"Open Dashboard","View Output").then(x=>{x==="Open Dashboard"?ee.createOrShow(t.extensionUri,m):x==="View Output"&&$.show(!0)})})),t.subscriptions.push(f.commands.registerCommand("secret-leak-detector.openDashboard",()=>{ee.createOrShow(t.extensionUri,e.getAllFindings())})),t.subscriptions.push(f.commands.registerCommand("secret-leak-detector.installGitHook",async()=>{let c=r().get("blockGitCommits",!0),p=Fe(r().get("failOn",B)),u=await o.installPreCommitHook(d,process.execPath,c,p);u.success?f.window.showInformationMessage(`\u{1F6E1}\uFE0F ${u.message}`):f.window.showErrorMessage(`Failed to install hook: ${u.message}`)})),t.subscriptions.push(f.commands.registerCommand("secret-leak-detector.uninstallGitHook",async()=>{let c=await o.uninstallPreCommitHook();c.success?f.window.showInformationMessage(`\u{1F6E1}\uFE0F ${c.message}`):f.window.showErrorMessage(`Failed to uninstall hook: ${c.message}`)})),t.subscriptions.push(f.commands.registerCommand("secret-leak-detector.ignoreFinding",async c=>{let p=c;if(!p){let m=e.getAllFindings();if(m.length===0){f.window.showInformationMessage("No active findings to ignore.");return}let h=await f.window.showQuickPick(m.map(v=>({label:`${v.type} (${v.file}:${v.line})`,description:v.redactedSecret,id:v.id})),{placeHolder:"Select a finding to ignore (suppress as false-positive)"});if(!h)return;p=h.id}e.ignoreFinding(p);let u=e.getIgnoredFindings();await t.workspaceState.update("ignoredFindings",u),f.window.showInformationMessage("\u{1F6E1}\uFE0F Finding marked as false-positive and suppressed.")})),t.subscriptions.push(f.commands.registerCommand("secret-leak-detector.unignoreFinding",async()=>{let c=e.getIgnoredFindings();if(c.length===0){f.window.showInformationMessage("No suppressed findings to restore.");return}let p=await f.window.showQuickPick(c.map(m=>({label:m})),{placeHolder:"Select a suppressed finding to restore"});if(!p)return;let u=c.filter(m=>m!==p.label);e.setIgnoredFindings(u),await t.workspaceState.update("ignoredFindings",u),f.window.activeTextEditor&&e.scanDocument(f.window.activeTextEditor.document),f.window.showInformationMessage(`\u{1F6E1}\uFE0F Restored finding '${p.label}'.`)})),t.subscriptions.push(f.commands.registerCommand("secret-leak-detector.remediateFinding",async(c,p,u)=>{await se.executeRemediation(c,p,u)})),t.subscriptions.push(f.commands.registerCommand("secret-leak-detector.clearFindings",()=>{e.clear(),f.window.showInformationMessage("Secret Leak Detector: All findings cleared.")})),o.isGitRepo().then(c=>{i.update(0,c)})}function sn(){for(let t of fe.values())clearTimeout(t);fe.clear()}0&&(module.exports={activate,deactivate});
