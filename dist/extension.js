"use strict";var tt=Object.create;var q=Object.defineProperty;var nt=Object.getOwnPropertyDescriptor;var it=Object.getOwnPropertyNames;var st=Object.getPrototypeOf,ot=Object.prototype.hasOwnProperty;var rt=(t,e)=>{for(var n in e)q(t,n,{get:e[n],enumerable:!0})},Se=(t,e,n,i)=>{if(e&&typeof e=="object"||typeof e=="function")for(let s of it(e))!ot.call(t,s)&&s!==n&&q(t,s,{get:()=>e[s],enumerable:!(i=nt(e,s))||i.enumerable});return t};var T=(t,e,n)=>(n=t!=null?tt(st(t)):{},Se(e||!t||!t.__esModule?q(n,"default",{value:t,enumerable:!0}):n,t)),at=t=>Se(q({},"__esModule",{value:!0}),t);var At={};rt(At,{activate:()=>kt,deactivate:()=>St});module.exports=at(At);var m=T(require("vscode"));var w=T(require("vscode"));var Ae=[{id:"aws-access-key",name:"AWS Access Key ID",provider:"Amazon Web Services",pattern:/\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b/g,baseConfidence:98,baseRiskWeight:95,signals:["AWS IAM standard 20-character key prefix (AKIA/ASIA/ABIA/ACCA)","Deterministic uppercase alphanumeric structure","Direct cloud resource control & hijacking capability"],suggestedEnvName:()=>"AWS_ACCESS_KEY_ID",remediationInstructions:["Revoke the exposed Access Key ID immediately in AWS IAM Management Console.","Check AWS CloudTrail logs for unauthorized API calls originated by this key.","Transition to IAM Roles for Amazon EC2 or AWS IAM Identity Center (SSO).","Never store access keys in source code; use AWS_ACCESS_KEY_ID environment variable."]},{id:"aws-secret-key",name:"AWS Secret Access Key",provider:"Amazon Web Services",pattern:/["']?(?:aws_secret_access_key|aws_secret_key|secret_access_key)["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?(?:[\s\r\n;,)]|$)/gi,baseConfidence:94,baseRiskWeight:95,minEntropy:4.1,signals:["Contextual AWS credential parameter match","High-entropy 40-character Base64 payload","Pairs with AWS Access Key for root/IAM API authentication"],suggestedEnvName:()=>"AWS_SECRET_ACCESS_KEY",remediationInstructions:["Rotate the key pair immediately in the AWS IAM Console.","Audit AWS KMS and S3 bucket accesses during exposure window.","Store secrets in AWS Secrets Manager or Parameter Store."]},{id:"github-pat",name:"GitHub Personal Access Token",provider:"GitHub",pattern:/\b(gh[pousr]_[A-Za-z0-9_]{36,255}|github_pat_[A-Za-z0-9_]{82})\b/g,baseConfidence:99,baseRiskWeight:95,signals:["Official GitHub token format prefix (ghp_, gho_, ghu_, ghs_, github_pat_)","Deterministic token structure and length","Permits repository code modification, workflow execution, or release poisoning"],suggestedEnvName:()=>"GITHUB_TOKEN",remediationInstructions:["Revoke token immediately at https://github.com/settings/tokens.","Check GitHub Security Audit Log for unauthorized repository clones or writes.","Use GitHub fine-grained PATs with scoped repository permissions.","Use GitHub Actions secrets rather than personal tokens for CI/CD."]},{id:"google-api-key",name:"Google Cloud / Gemini API Key",provider:"Google Cloud",pattern:/\b(AIza[0-9A-Za-z_-]{34,35})\b/g,baseConfidence:96,baseRiskWeight:90,minEntropy:3.5,signals:["Google standard AIza service key signature","Fixed 39-character alphanumeric structure","Access to Google Cloud Platform APIs and billing services"],suggestedEnvName:()=>"GEMINI_API_KEY",remediationInstructions:["Restrict or delete the API key in Google Cloud Console Credentials page.","Apply API restrictions (e.g. restrict solely to Generative Language API).","Apply HTTP referrer or IP address restrictions.","Store in GEMINI_API_KEY environment variable."]},{id:"openai-api-key",name:"OpenAI API Key",provider:"OpenAI",pattern:/\b(sk-(?:proj|admin|svcacct)-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{20,48})\b/g,baseConfidence:97,baseRiskWeight:92,minEntropy:4,signals:["OpenAI official secret prefix (sk-proj- or sk-)","High Shannon entropy key payload","Direct account credit exhaustion and model theft risk"],suggestedEnvName:()=>"OPENAI_API_KEY",remediationInstructions:["Revoke key at https://platform.openai.com/api-keys.","Verify credit consumption in OpenAI usage dashboard.","Inject credentials using OPENAI_API_KEY environment variable."]},{id:"anthropic-api-key",name:"Anthropic Claude API Key",provider:"Anthropic",pattern:/\b(sk-ant-[A-Za-z0-9_-]{30,})\b/g,baseConfidence:98,baseRiskWeight:92,minEntropy:3.8,signals:["Anthropic official secret token signature (sk-ant-)","High entropy cryptographic token payload","Direct Claude model API billing access"],suggestedEnvName:()=>"ANTHROPIC_API_KEY",remediationInstructions:["Revoke the API key in Anthropic Console.","Generate replacement key with spend limit configured.","Inject via ANTHROPIC_API_KEY environment variable."]},{id:"huggingface-token",name:"Hugging Face Access Token",provider:"Hugging Face",pattern:/\b(hf_[A-Za-z0-9]{34})\b/g,baseConfidence:98,baseRiskWeight:88,minEntropy:3.8,signals:["Hugging Face user access token format (hf_ prefix + 34 chars)","Grants access to gated AI models, private repositories, and inference endpoints"],suggestedEnvName:()=>"HF_TOKEN",remediationInstructions:["Revoke token immediately at https://huggingface.co/settings/tokens.","Audit access logs for unauthorized model downloads.","Inject credentials using the HF_TOKEN environment variable."]},{id:"stripe-secret-key",name:"Stripe Secret Key",provider:"Stripe",pattern:/\b((?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,100})\b/g,baseConfidence:97,baseRiskWeight:96,signals:["Stripe signature prefix (sk_live / rk_live / sk_test)","Financial transaction and customer credit card access","High financial liability and compliance breach"],suggestedEnvName:()=>"STRIPE_SECRET_KEY",remediationInstructions:["Roll API key immediately in Stripe Dashboard > Developers > API keys.","Audit recent transactions and payout bank account modifications.","Never bundle Stripe secret keys in frontend or mobile client builds."]},{id:"slack-bot-token",name:"Slack OAuth / Bot Token",provider:"Slack",pattern:/\b(xox[baprs]-[0-9A-Za-z-]{10,72})\b/g,baseConfidence:95,baseRiskWeight:82,signals:["Slack OAuth bot/user prefix (xoxb/xoxp/xoxa)","Internal company communications and workspace access"],suggestedEnvName:()=>"SLACK_BOT_TOKEN",remediationInstructions:["Revoke token in api.slack.com/apps.","Re-install app with minimal necessary OAuth scopes."]},{id:"slack-webhook",name:"Slack Incoming Webhook URL",provider:"Slack",pattern:/(https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9_]{8,12}\/B[A-Z0-9_]{8,12}\/[A-Za-z0-9_]{24})/g,baseConfidence:98,baseRiskWeight:78,signals:["Slack Incoming Webhook URL structure","Enables unauthorized message spoofing and channel phishing"],suggestedEnvName:()=>"SLACK_WEBHOOK_URL",remediationInstructions:["Delete the exposed webhook URL in Slack App settings.","Generate a new webhook URL and store in SLACK_WEBHOOK_URL."]},{id:"azure-storage-key",name:"Azure Shared Storage Key",provider:"Microsoft Azure",pattern:/["']?(?:AccountKey|azure_secret|azure_key)["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{86,88}==)(?:["';,\s\r\n)]|$)/gi,baseConfidence:93,baseRiskWeight:90,minEntropy:4.2,signals:["Azure storage account key signature (86-88 chars base64 with == padding)","Full administrative access to Azure Blob/Queue/Table storage"],suggestedEnvName:()=>"AZURE_STORAGE_KEY",remediationInstructions:["Regenerate storage key in Azure Portal.","Adopt Azure Managed Identity or Microsoft Entra ID authentication instead."]},{id:"private-key",name:"Cryptographic Private Key (PEM)",provider:"Cryptography",pattern:/(-----BEGIN (?:[A-Z0-9_-]+ )*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END (?:[A-Z0-9_-]+ )*PRIVATE KEY(?: BLOCK)?-----)/g,baseConfidence:100,baseRiskWeight:100,signals:["Standard PEM container header and footer","Unencrypted cryptographic private key","Total server impersonation, SSH compromise, or TLS decryption risk"],suggestedEnvName:()=>"PRIVATE_KEY_PATH",remediationInstructions:["Immediately decommission this private key pair.","Remove public key counterpart from all servers authorized_keys.","Never commit private keys to version control; use SSH agents or secret vaults."]},{id:"database-url",name:"Database Connection String with Credentials",provider:"Database",pattern:/\b((?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis):\/\/[^:\s'"]+:([^\s'"]+)@([a-zA-Z0-9_.-]+\.[a-zA-Z0-9_.-]+|localhost|127\.0\.0\.1|\[[0-9a-fA-F:]+\])(?::[0-9]+)?(?:\/[^\s'"`;]*)?)/gi,baseConfidence:92,baseRiskWeight:88,minEntropy:3.2,signals:["Database connection URL containing embedded user:password credentials","Direct data exfiltration, deletion, or ransomware risk"],suggestedEnvName:()=>"DATABASE_URL",remediationInstructions:["Rotate the database user password immediately on the database server.","Migrate connection string to DATABASE_URL environment variable.","Enable SSL/TLS requirement and VPC network access controls."]},{id:"jwt-token",name:"JSON Web Token (JWT)",provider:"Auth / Identity",pattern:/\b(ey[A-Za-z0-9_-]{15,}\.ey[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{10,})\b/g,baseConfidence:88,baseRiskWeight:75,minEntropy:4.1,signals:["Header.Payload.Signature Base64 tripartite JWT structure","Authentication session hijacking and privilege escalation"],suggestedEnvName:t=>t?.toUpperCase()||"AUTH_TOKEN",remediationInstructions:["Invalidate active sessions / revoke refresh token family in identity provider.","Never hardcode tokens in client or backend source repositories."]},{id:"gitlab-pat",name:"GitLab Personal Access Token",provider:"GitLab",pattern:/\b(glpat-[0-9a-zA-Z_-]{20,40})\b/g,baseConfidence:98,baseRiskWeight:90,signals:["GitLab personal access token prefix (glpat-)","Repository read/write and CI/CD control"],suggestedEnvName:()=>"GITLAB_TOKEN",remediationInstructions:["Revoke token in GitLab User Settings > Access Tokens.","Store in GITLAB_TOKEN environment variable."]},{id:"npm-access-token",name:"npm Access Token",provider:"npm",pattern:/\b(npm_[A-Za-z0-9]{36})\b/g,baseConfidence:99,baseRiskWeight:92,signals:["npm official access token prefix (npm_)","Package publication and account takeover capability"],suggestedEnvName:()=>"NPM_TOKEN",remediationInstructions:["Revoke token immediately at https://www.npmjs.com/settings/tokens.","Store in NPM_TOKEN environment variable."]},{id:"sendgrid-api-key",name:"SendGrid API Key",provider:"SendGrid",pattern:/\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b/g,baseConfidence:99,baseRiskWeight:85,signals:["SendGrid standard tripartite API key (SG.<22>.<43>)","Email spoofing and communication channel hijacking risk"],suggestedEnvName:()=>"SENDGRID_API_KEY",remediationInstructions:["Revoke key in SendGrid dashboard Settings > API Keys.","Store in SENDGRID_API_KEY environment variable."]},{id:"twilio-api-key",name:"Twilio API Key / Auth Token",provider:"Twilio",pattern:/\b((?:SK|AC)[0-9a-fA-F]{32})\b/g,baseConfidence:95,baseRiskWeight:85,signals:["Twilio Account SID (AC) or API Key (SK) prefix followed by 32 hex chars","Telephony API and SMS billing access"],suggestedEnvName:()=>"TWILIO_AUTH_TOKEN",remediationInstructions:["Rotate token in Twilio Console.","Store in TWILIO_AUTH_TOKEN environment variable."]},{id:"password-assignment",name:"Password in Source Code",provider:"Generic Credential",pattern:/["']?(?:password|passwd|pwd|db_password|db_pass)["']?\s*[:=]\s*["']([^"'\r\n\s]{8,64})["']/gi,baseConfidence:82,baseRiskWeight:80,minEntropy:2.8,signals:["Hard-coded password assignment","Credential exposure in plain text"],suggestedEnvName:()=>"PASSWORD",remediationInstructions:["Rotate password immediately.","Store password in an environment variable or secrets manager.","Never commit plain passwords to version control."]},{id:"generic-api-key",name:"Generic API Secret Assignment",provider:"Generic Credential",pattern:/["']?(?:api_?key|secret_?key|auth_?token|client_?secret|access_?token|private_?key)["']?\s*[:=]\s*["']?([A-Za-z0-9_.~/+=]{20,90})["']?(?:[\s\r\n;,)]|$)/gi,baseConfidence:80,baseRiskWeight:70,minEntropy:3.5,signals:["Sensitive identifier keyword assignment","High Shannon entropy string literal"],suggestedEnvName:t=>t?t.toUpperCase():"API_KEY",remediationInstructions:["Identify corresponding API provider and rotate credential.","Migrate credential to local .env file (ensure .env is in .gitignore)."]}];var J=T(require("path")),ct=[/api[_-]?key/i,/secret[_-]?key/i,/access[_-]?token/i,/auth[_-]?token/i,/private[_-]?key/i,/client[_-]?secret/i,/password/i,/credential/i,/session[_-]?token/i,/bearer/i,/aws[_-]?(?:access|secret)/i,/stripe[_-]?(?:secret|key)/i,/github[_-]?(?:token|pat)/i,/slack[_-]?token/i,/db[_-]?pass(?:word)?/i],dt=[/placeholder/i,/mock/i,/dummy/i,/fake/i,/sample/i,/test[_-]?(?:key|token|id)/i,/demo/i,/insert[_-]?here/i];function Ee(t){let e=t.replace(/\\/g,"/").toLowerCase(),n=J.basename(t).toLowerCase(),i=J.extname(t).toLowerCase(),s=/(?:^|\/)(?:tests?|specs?|__tests__|__mocks__|fixtures|mocks)\//i.test(e)||/[._-](?:test|spec)\.[a-z0-9]+$/i.test(n)||/^(?:test|spec)\.[a-z0-9]+$/i.test(n),o=/(?:^|\/)(?:docs|doc|documentation|tutorials|guides)\/|readme\.md|contributing\.md|changelog\.md/i.test(e),r=/(?:^|\/)(?:example|sample|\.example|\.sample)/i.test(e)||/[._-](?:example|sample)\.[a-z0-9]+$/i.test(n),c=/^\.env(?:\.[a-z0-9]+)?$/.test(n)||/(?:config|settings|secret|credential|database|deploy|production|staging|k8s|helm|tfvars)/i.test(e)||[".env",".yaml",".yml",".json",".toml",".ini",".tf"].includes(i),p=/^\.env/.test(n)||/(?:secret|credential|id_rsa|private_key|keypair|auth_config)/i.test(n);return{fileExtension:i,isConfig:c,isTest:s,isDoc:o,isSensitiveName:p,isExampleOrSample:r}}function ue(t,e){let n=t[e]||"",i=[];for(let h=Math.max(0,e-3);h<e;h++)i.push(t[h]);let s=[];for(let h=e+1;h<Math.min(t.length,e+4);h++)s.push(t[h]);let o,r=n.match(/(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*[:=]/),c=n.match(/["']?([a-zA-Z0-9_$-]+)["']?\s*[:=]/);r?o=r[1]:c&&(o=c[1]);let p=o?ct.some(h=>h.test(o)):!1,a=o?dt.some(h=>h.test(o)):!1,l=/[:=]/.test(n),d=/(?:process\.env|os\.environ|dotenv|config|getenv)/i.test(n),g=/(?:authorization|bearer|x-api-key)/i.test(n),f=/^\s*(?:\/\/|#|\/\*|\*|--)/.test(n);return{inferredVariable:o,isSensitiveIdentifier:p,isBenignIdentifier:a,isAssignment:l,isEnvOrConfigAccess:d,isHeaderOrBearer:g,isInComment:f,surroundingBefore:i,matchedLine:n,surroundingAfter:s}}var X=/(?:api_?key|secret|token|password|auth|credential|access_?key|private_?key)/i,Ce=/(?:console\.(?:log|warn|error|info|debug)|logger\.|print\(|logging\.)/i,Q=null;try{Q=require("typescript")}catch{Q=null}function ge(t,e,n){let i=t[e]||"";if(Q&&(!n||/\.[jt]sx?$|\.m[jt]s$|\.c[jt]s$/i.test(n))){let o,r;if(t.length>60){let p=Math.max(0,e-30),a=Math.min(t.length,e+30);o=t.slice(p,a).join(`
`),r=e-p}else o=t.join(`
`),r=e;let c=lt(o,r);if(c)return c}return pt(i)}function lt(t,e){try{let a=function(l){if(!p&&!(l.pos>c||l.end<r)&&(i.forEachChild(l,a),!p)){if(l.kind===i.SyntaxKind.BinaryExpression&&(l.operatorToken.kind===i.SyntaxKind.BarBarToken||l.operatorToken.kind===i.SyntaxKind.QuestionQuestionToken)){let d=l.left.getText(s);if(d.includes("process.env")||d.includes("env")||d.toLowerCase().includes("key")){p={variablePath:d,isSensitiveProperty:X.test(d),isEnvFallback:!0,isAuthorizationHeader:!1,isLoggingCall:!1,scopeType:"ENV_FALLBACK"};return}}if(l.kind===i.SyntaxKind.PropertyAssignment){let d=l.name.getText(s),g=d,f=l.parent;for(;f;)f.kind===i.SyntaxKind.PropertyAssignment&&f.name?g=`${f.name.getText(s)}.${g}`:f.kind===i.SyntaxKind.VariableDeclaration&&f.name&&(g=`${f.name.getText(s)}.${g}`),f=f.parent;let h=X.test(g),u=/authorization|bearer|x-api-key/i.test(d);p={variablePath:g,isSensitiveProperty:h,isEnvFallback:!1,isAuthorizationHeader:u,isLoggingCall:!1,scopeType:u?"HEADER":"OBJECT_PROPERTY"};return}if(l.kind===i.SyntaxKind.CallExpression){let d=l.expression.getText(s);if(Ce.test(d)){p={variablePath:d,isSensitiveProperty:!1,isEnvFallback:!1,isAuthorizationHeader:!1,isLoggingCall:!0,scopeType:"FUNCTION_ARG"};return}}if(l.kind===i.SyntaxKind.VariableDeclaration){let d=l.name.getText(s);p={variablePath:d,isSensitiveProperty:X.test(d),isEnvFallback:!1,isAuthorizationHeader:!1,isLoggingCall:!1,scopeType:"VARIABLE_DECLARATION"};return}}};var n=a;let i=Q,s=i.createSourceFile("eval_target.tsx",t,i.ScriptTarget.Latest,!0,i.ScriptKind.TSX),o=s.getLineStarts();if(e>=o.length)return null;let r=o[e],c=e+1<o.length?o[e+1]-1:t.length,p=null;return a(s),p}catch{return null}}function pt(t){let e=Ce.test(t),n=/(?:process\.env\.[A-Za-z0-9_]+|os\.(?:getenv|environ\.get)\([^)]+\))\s*(?:\|\||\?\?)\s*["'][^"']+["']/.test(t),i=/(?:authorization|x-api-key|bearer)\s*[:=]/i.test(t),s=t.match(/([a-zA-Z0-9_$.]+)\s*[:=]\s*["'][^"']+["']/)||t.match(/["']([a-zA-Z0-9_.]+)["']\s*:\s*["'][^"']+["']/),o,r=!1;s&&(o=s[1],r=X.test(o));let c="UNKNOWN";return n?c="ENV_FALLBACK":i?c="HEADER":o&&o.includes(".")?c="OBJECT_PROPERTY":o?c="VARIABLE_DECLARATION":e&&(c="FUNCTION_ARG"),{variablePath:o,isSensitiveProperty:r,isEnvFallback:n,isAuthorizationHeader:i,isLoggingCall:e,scopeType:c}}function me(t){if(!t||t.length===0)return 0;let e={};for(let s of t)e[s]=(e[s]||0)+1;let n=0,i=t.length;for(let s in e){let o=e[s]/i;n-=o*Math.log2(o)}return Math.round(n*100)/100}function fe(t){return/^[0-9a-fA-F]+$/.test(t)?{setName:"HEX",baseSize:16}:/^[A-Za-z0-9+/=_-]+$/.test(t)?{setName:"BASE64",baseSize:64}:/^[A-Za-z0-9]+$/.test(t)?{setName:"ALPHANUMERIC",baseSize:62}:/^[\x20-\x7E]+$/.test(t)?{setName:"ASCII_PRINTABLE",baseSize:95}:{setName:"SPECIAL",baseSize:128}}function xe(t){if(!t||t.length===0)return 0;let e=me(t),{baseSize:n}=fe(t),i=Math.log2(n);if(i<=0)return 0;let s=Math.min(1,e/i);return Math.round(s*100)/100}var ut=[/\bplaceholder\b/i,/\byour[_-]?(?:api)?[_-]?key\b/i,/\byour[_-]?secret\b/i,/\byour[_-]?token\b/i,/\binsert[_-]?here\b/i,/\breplace[_-]?me\b/i,/\benter[_-]?your\b/i,/\bchange[_-]?me\b/i,/\bdummy\b/i,/\bfake[_-]?token\b/i,/xxxx+/i,/\btest[_-]?value\b/i,/AKIAIOSFODNN7EXAMPLE/i,/wJalrXUtnFEMI\/K7MDENG\/bPxRfiCYEXAMPLEKEY/i,/^123456789[0-9]*$/,/^abcdef[a-z0-9]*$/i,/00000000[0-9]*/,/sk_live_example/i,/ghp_example/i,/:\/\/[^:]+:(?:password|secret|changeme|pass|admin|test|postgres|root)@(?:localhost|127\.0\.0\.1)(?::\d+)?\b/i,/:\/\/(?:postgres|root):(postgres|root)@(?:localhost|127\.0\.0\.1)(?::\d+)?\b/i],gt=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,mt=/^(?:mock|dummy|placeholder|fake|sample)_(?:key|token|secret|password|pwd|cred)$/i;function we(t,e,n){for(let s of ut)if(s.test(t))return{isFalsePositive:!0,reason:`Matched known documentation/placeholder pattern: ${s.source}`,confidencePenalty:100};if(e&&mt.test(e)&&!t.startsWith("AKIA")&&!t.startsWith("ghp_"))return{isFalsePositive:!0,reason:`Variable identifier indicates placeholder: ${e}`,confidencePenalty:100};let i=new Set(t.split("")).size;if(t.length>=10&&i<=3)return{isFalsePositive:!0,reason:"Low character diversity (repetitive filler characters)",confidencePenalty:95};if(gt.test(t)&&!e?.match(/secret|token|api_?key/i))return{isFalsePositive:!0,reason:"Standard UUID identifier without credential context",confidencePenalty:90};if(n){let s=/(?:docs|documentation|tutorials|guides)\/|readme\.md/i.test(n);if(/(?:example|sample|\.example|\.sample)/i.test(n)&&/example|your_/i.test(t))return{isFalsePositive:!0,reason:"Sample configuration value inside template/example file",confidencePenalty:90};if(s&&!t.startsWith("ghp_")&&!t.startsWith("AKIA"))return{isFalsePositive:!1,confidencePenalty:25}}return{isFalsePositive:!1,confidencePenalty:0}}function Ie(t){if(!/^(AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}$/.test(t))return{isValid:!1,confidenceBonus:0,reason:"Invalid AWS key length or character set"};let e=t.substring(0,4);return{isValid:!0,confidenceBonus:10,reason:{AKIA:"Standard permanent IAM user access key",ASIA:"Temporary STS session access key",ABIA:"AWS Backup access key",ACCA:"AWS CodeCommit access key"}[e]||"Valid AWS Access Key ID structure"}}function Re(t){let e=/^sk_live_[0-9a-zA-Z]{24,100}$/.test(t)||/^rk_live_[0-9a-zA-Z]{24,100}$/.test(t),n=/^sk_test_[0-9a-zA-Z]{24,100}$/.test(t)||/^rk_test_[0-9a-zA-Z]{24,100}$/.test(t);return!e&&!n?{isValid:!1,confidenceBonus:0,reason:"Does not match official Stripe secret key format"}:{isValid:!0,confidenceBonus:e?12:5,reason:e?"Production live Stripe Secret Key":"Stripe Test API key"}}function Te(t){return/^ghp_[A-Za-z0-9_]{36}$/.test(t)?{isValid:!0,confidenceBonus:12,reason:"GitHub Personal Access Token (Classic)"}:/^gho_[A-Za-z0-9_]{36}$/.test(t)?{isValid:!0,confidenceBonus:10,reason:"GitHub OAuth Access Token"}:/^ghs_[A-Za-z0-9_]{36}$/.test(t)?{isValid:!0,confidenceBonus:10,reason:"GitHub Server-to-server token"}:/^github_pat_[A-Za-z0-9_]{82}$/.test(t)?{isValid:!0,confidenceBonus:15,reason:"GitHub Fine-Grained Personal Access Token"}:{isValid:!1,confidenceBonus:0,reason:"Invalid GitHub token prefix or length"}}function _e(t){let e=t.split(".");if(e.length!==3)return{isValid:!1,confidenceBonus:0,reason:"Not a 3-part dot-separated JWT"};try{let n=Buffer.from(e[0],"base64url").toString("utf8"),i=JSON.parse(n);if(i&&typeof i=="object"&&i.alg)return{isValid:!0,confidenceBonus:15,reason:`Valid JWT structure with signature algorithm: ${i.alg}`}}catch{}return{isValid:!1,confidenceBonus:0,reason:"Malformed JWT header JSON payload"}}function Fe(t){try{let e=new URL(t);if(!["postgres:","postgresql:","mysql:","mongodb:","mongodb+srv:","redis:"].includes(e.protocol))return{isValid:!1,confidenceBonus:0,reason:"Unsupported database protocol scheme"};if(e.password&&e.password.length>0)return{isValid:!0,confidenceBonus:12,reason:`Database connection string containing credentials for user '${e.username||"default"}'`}}catch{let e=/^(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis):\/\/[^:\s'"]+:([^\s'"]+)@([a-zA-Z0-9_.-]+(?::[0-9]+)?\/[^\s'"`;]*)/i,n=t.match(e);if(n&&n[1])return{isValid:!0,confidenceBonus:10,reason:"Database connection URI structure matched with embedded password"}}return{isValid:!1,confidenceBonus:0,reason:"Invalid database connection URL structure"}}function Pe(t){return/^sk-proj-[A-Za-z0-9_-]{48,}$/.test(t)?{isValid:!0,confidenceBonus:15,reason:"Valid OpenAI Project API Key format"}:/^sk-admin-[A-Za-z0-9_-]{48,}$/.test(t)?{isValid:!0,confidenceBonus:15,reason:"Valid OpenAI Admin/Organization API Key format"}:/^sk-svcacct-[A-Za-z0-9_-]{48,}$/.test(t)?{isValid:!0,confidenceBonus:15,reason:"Valid OpenAI Service Account Key format"}:/^sk-[A-Za-z0-9]{32,48}$/.test(t)?{isValid:!0,confidenceBonus:10,reason:"Valid OpenAI Standard/Legacy API Key format"}:{isValid:!1,confidenceBonus:0,reason:"Invalid OpenAI API key structure"}}function $e(t){return/^sk-ant-[A-Za-z0-9_-]{40,}$/.test(t)?{isValid:!0,confidenceBonus:15,reason:"Valid Anthropic Claude API Key format"}:{isValid:!1,confidenceBonus:0,reason:"Invalid Anthropic API key format"}}function De(t){return/^AIza[0-9A-Za-z_-]{35}$/.test(t)?{isValid:!0,confidenceBonus:12,reason:"Valid Google Cloud / Gemini AIza service key signature"}:{isValid:!1,confidenceBonus:0,reason:"Invalid Google Cloud API key format"}}function Le(t){return/^xox[baprs]-[0-9A-Za-z-]{10,72}$/.test(t)?{isValid:!0,confidenceBonus:12,reason:`Valid Slack ${t.startsWith("xoxb")?"Bot Token":t.startsWith("xoxp")?"User Token":"OAuth Token"} signature`}:{isValid:!1,confidenceBonus:0,reason:"Invalid Slack token structure"}}function Ne(t){return/^hf_[A-Za-z0-9]{34}$/.test(t)?{isValid:!0,confidenceBonus:12,reason:"Valid Hugging Face User Access Token format"}:{isValid:!1,confidenceBonus:0,reason:"Invalid Hugging Face token structure"}}function he(t,e,n,i,s,o){let r=[],c=t.baseConfidence;r.push({signal:"KNOWN_PATTERN_MATCH",description:`Matched recognized credential signature for ${t.provider} (${t.name})`,confidenceImpact:0,details:{ruleId:t.id,provider:t.provider}});let p=me(e),a=xe(e),{setName:l}=fe(e);if(t.minEntropy&&p<t.minEntropy?(c=Math.max(10,c-30),r.push({signal:"LOW_ENTROPY",description:`Low entropy score: ${p} bits/char below minimum threshold of ${t.minEntropy}`,confidenceImpact:-30,details:{shannonEntropy:p,minEntropy:t.minEntropy}})):p>=4.5?(c=Math.min(100,c+5),r.push({signal:"HIGH_ENTROPY",description:`Cryptographic entropy: ${p} bits/char (${l} set), indicates non-human randomness`,confidenceImpact:5,details:{shannonEntropy:p,normalizedEntropy:a,characterSet:l}})):p>=3.4?r.push({signal:"MODERATE_ENTROPY",description:`Moderate entropy: ${p} bits/char (${l} set)`,confidenceImpact:0,details:{shannonEntropy:p,normalizedEntropy:a,characterSet:l}}):(c=Math.max(10,c-15),r.push({signal:"LOW_ENTROPY",description:`Low entropy score: ${p} bits/char (${l} set)`,confidenceImpact:-15,details:{shannonEntropy:p,normalizedEntropy:a,characterSet:l}})),i.isSensitiveIdentifier||o?.isSensitiveProperty){let u=o?.variablePath||i.inferredVariable||"credential";c=Math.min(100,c+10),r.push({signal:"SENSITIVE_IDENTIFIER",description:`Assigned to sensitive identifier / property: '${u}'`,confidenceImpact:10,details:{identifier:u}})}else i.isBenignIdentifier&&(c=Math.max(10,c-25),r.push({signal:"BENIGN_IDENTIFIER",description:`Identifier name indicates mock or sample value: '${i.inferredVariable}'`,confidenceImpact:-25,details:{identifier:i.inferredVariable}}));o?.isEnvFallback&&(c=Math.min(100,c+12),r.push({signal:"ENV_FALLBACK_ASSIGNMENT",description:'Hardcoded literal provided as environment variable fallback (e.g. process.env.KEY || "...")',confidenceImpact:12})),o?.isAuthorizationHeader&&(c=Math.min(100,c+10),r.push({signal:"AUTHORIZATION_HEADER",description:"Passed in HTTP Authorization or Bearer token header context",confidenceImpact:10})),(n.isConfig||n.isSensitiveName)&&(c=Math.min(100,c+8),r.push({signal:"PRODUCTION_CONFIG_FILE",description:`Located in configuration or secret storage file (${n.fileExtension})`,confidenceImpact:8,details:{isConfig:n.isConfig,extension:n.fileExtension}})),n.isTest&&(c=Math.max(20,c-20),r.push({signal:"TEST_FILE_PENALTY",description:"Found inside test/mock directory structure",confidenceImpact:-20})),n.isDoc&&(c=Math.max(20,c-25),r.push({signal:"DOCUMENTATION_PENALTY",description:"Found inside documentation or markdown guide",confidenceImpact:-25}));let d;t.id==="aws-access-key"?d=Ie(e):t.id==="stripe-secret-key"?d=Re(e):t.id==="github-pat"?d=Te(e):t.id==="jwt-token"?d=_e(e):t.id==="database-url"?d=Fe(e):t.id==="openai-api-key"?d=Pe(e):t.id==="anthropic-api-key"?d=$e(e):t.id==="google-api-key"?d=De(e):t.id==="slack-bot-token"?d=Le(e):t.id==="huggingface-token"&&(d=Ne(e)),d&&d.isValid&&(c=Math.min(100,c+d.confidenceBonus),r.push({signal:"STRUCTURAL_VALIDATION_PASSED",description:`Structural validation verified: ${d.reason}`,confidenceImpact:d.confidenceBonus}));let g=we(e,i.inferredVariable,s);if(g.isFalsePositive)return{confidence:0,evidence:{items:[{signal:"KNOWN_PLACEHOLDER_REJECTED",description:g.reason||"Placeholder value rejected",confidenceImpact:-100}],shannonEntropy:p,normalizedEntropy:a,characterSet:l,surroundingCode:{before:i.surroundingBefore,targetLine:i.matchedLine,after:i.surroundingAfter,inferredVariable:i.inferredVariable},fileContext:{fileExtension:n.fileExtension,isConfig:n.isConfig,isTest:n.isTest,isDoc:n.isDoc,isSensitiveName:n.isSensitiveName,isExampleOrSample:n.isExampleOrSample}},isSuppressed:!0,suppressReason:g.reason};g.confidencePenalty>0&&(c=Math.max(10,c-g.confidencePenalty));let f=Math.max(0,Math.min(100,Math.round(c))),h={items:r,shannonEntropy:p,normalizedEntropy:a,characterSet:l,surroundingCode:{before:i.surroundingBefore,targetLine:i.matchedLine,after:i.surroundingAfter,inferredVariable:i.inferredVariable},fileContext:{fileExtension:n.fileExtension,isConfig:n.isConfig,isTest:n.isTest,isDoc:n.isDoc,isSensitiveName:n.isSensitiveName,isExampleOrSample:n.isExampleOrSample}};return{confidence:f,evidence:h,isSuppressed:!1}}function ve(t,e,n,i){let s=[],o=0,r=Math.min(40,Math.round(t.baseRiskWeight/100*40));o+=r,s.push({factor:"CREDENTIAL_SEVERITY",weight:40,scoreContribution:r,explanation:`${t.provider} ${t.name} has high inherent privilege capability`});let c=Math.round(e/100*25);o+=c,s.push({factor:"CONFIDENCE_LEVEL",weight:25,scoreContribution:c,explanation:`Multi-signal verification confidence is ${e}%`});let p=5,a="Standard source code file";n.isConfig||n.isSensitiveName?(p=15,a="Located in sensitive deployment / environment configuration"):n.isTest?(p=0,a="Located in test / fixture codebase with reduced operational blast radius"):n.isDoc&&(p=0,a="Located in documentation context"),o+=p,s.push({factor:"STORAGE_ENVIRONMENT",weight:15,scoreContribution:p,explanation:a});let l=5,d="Found in local uncommitted working tree";i&&(i.isRemote?(l=20,d="Pushed to remote repository branch (external exposure risk)"):i.isPresentInHistory?(l=16,d=`Committed to Git history across ${i.branches.length||1} branch(es) (${i.exposureDurationDays} days exposure)`):i.isPresentInHead&&(l=12,d="Committed in current HEAD commit")),o+=l,s.push({factor:"EXPOSURE_REACH",weight:20,scoreContribution:l,explanation:d});let g=Math.max(0,Math.min(100,Math.round(o))),f="LOW";g>=76?f="CRITICAL":g>=51?f="HIGH":g>=26?f="MEDIUM":f="LOW";let h=ft(g,i),u=`${f} Risk (${g}/100) \u2014 ${t.name}. ${h.summary}`;return{score:g,tier:f,factors:s,blastRadius:h,summary:u}}function ft(t,e){let n=[],i=Math.round(t*.5),s=e?e.isPresentInHead:!0,o=e?e.isPresentInHistory:!1,r=e?.isPresentInHistory?1:0,c=e?.branches||["main"],p=c.length,a=e?.isRemote||!1,l=e?.exposureDurationDays||0;s&&(n.push("Active working tree contains exposed secret"),i+=15),o&&(n.push(`Git history contains commit records across ${p} branch(es)`),i+=20),a&&(n.push("Secret has been synchronized to remote tracking branches"),i+=25),l>7&&(n.push(`Exposure duration exceeds ${l} days without rotation`),i+=10),i=Math.max(0,Math.min(100,i));let d="CONTAINED";i>=75?d="SEVERE":i>=50?d="EXTENSIVE":i>=25?d="MODERATE":d="CONTAINED";let g=`Blast Radius: ${d} (${i}/100) \u2014 ${a?"Remote & history exposure":o?"Historical commit exposure":"Contained to local working tree"}`;return{level:d,score:i,workingTreeExposed:s,gitHistoryExposed:o,commitCount:r,branchCount:p,branches:c,remoteExposed:a,exposureDurationDays:l,summary:g,factors:n}}var M=T(require("fs")),Me=T(require("path"));var Oe=T(require("crypto"));function U(t){if(!t)return"";let e=t.length;if(e<=8)return"\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022";let n=Math.min(4,Math.floor(e/4)),i=Math.min(3,Math.floor(e/4)),s=Math.max(4,e-n-i),o=t.substring(0,n),r=t.substring(e-i),c="\u2022".repeat(Math.min(12,s));return`${o}${c}${r}`}function j(t){return Oe.createHash("sha256").update(t).digest("hex").substring(0,16)}function ee(t){return t.replace(/\\/g,"\\\\").replace(/"/g,'\\"').replace(/\$/g,"\\$").replace(/\n/g,"\\n").replace(/\r/g,"\\r")}function be(t,e,n,i,s){let o=t.suggestedEnvName(s),r=`process.env.${o}`,c=U(e),p=ee(e),a=[`1. Revoke / rotate credential immediately with provider: ${t.provider}`,`2. Migrate secret value to local .env file (${o})`,`3. Replace hardcoded literal in ${n} with ${r}`,"4. Verify .env is listed in .gitignore so it is never committed","5. If committed previously, purge from Git history using git-filter-repo or BFG","6. Rescan file and commit to verify exposure is eliminated"],l=`${o}="${p}"`,d=`${o}=your_${o.toLowerCase()}_here`,g=`# WARNING: Use BFG Repo Cleaner to purge secrets from history (safer than filter-repo --invert-paths):
#   java -jar bfg.jar --replace-text secrets.txt <repo-dir>
# Where secrets.txt lists the exact literal to redact (one per line).
# Then force-push: git push --force --all && git push --force --tags
# Alternatively with git-filter-repo (rewrites content, not paths):
#   git filter-repo --replace-text secrets.txt`,f=`--- a/${n}
+++ b/${n}
@@ -${i},1 +${i},1 @@
- ... "${c}" ...
+ ... ${r} ...`;return{steps:a,envVarName:o,replacementCode:r,envFileSnippet:l,envExampleSnippet:d,gitHistoryPurgeCommand:g,diffPreview:f}}function Be(t,e,n){let i=t.split(/\r?\n/),s=new Map;for(let o of i){let r=o.trim();if(!r||r.startsWith("#"))continue;let c=r.indexOf("=");if(c!==-1){let p=r.substring(0,c).trim(),a=r.substring(c+1).trim();(a.startsWith('"')&&a.endsWith('"')||a.startsWith("'")&&a.endsWith("'"))&&(a=a.substring(1,a.length-1)),s.set(p,a)}}if(s.has(e)){let o=s.get(e);if(o===ee(n)||o===n)return{varName:e,isReused:!0};let r=2;for(;s.has(`${e}_${r}`);){if(s.get(`${e}_${r}`)===n)return{varName:`${e}_${r}`,isReused:!0};r++}return{varName:`${e}_${r}`,isReused:!1}}return{varName:e,isReused:!1}}function Ke(t){let e=Me.join(t,".gitignore");if(M.existsSync(e)){let n=M.readFileSync(e,"utf8");if(!n.split(/\r?\n/).some(o=>/^\s*\.env(?:\s|$)/.test(o))){let o=n.endsWith(`
`)||n.length===0?"":`
`;M.appendFileSync(e,`${o}# Credentials
.env
.env.*.local
`,"utf8")}}else M.writeFileSync(e,`# Credentials
.env
.env.*.local
`,"utf8");try{let{execFileSync:n}=require("child_process");try{throw n("git",["ls-files","--error-unmatch",".env"],{cwd:t,stdio:"ignore"}),new Error('.env is already tracked in Git index. Run "git rm --cached .env" to untrack it before storing secrets.')}catch(i){if(i.message&&i.message.includes("already tracked in Git index"))throw i}try{n("git",["check-ignore","-q",".env"],{cwd:t,stdio:"ignore"})}catch{throw new Error(".env is not ignored by Git according to git check-ignore.")}}catch(n){if(n.message&&(n.message.includes("already tracked")||n.message.includes("not ignored by Git")))throw n}}function Z(t,e,n={}){let i=typeof n=="string"?{workspaceRoot:n}:n,s=i.rules||Ae,o=i.workspaceRoot,r=Ee(e),c=[],p=null;function a(){if(!p){p=[0];for(let u=0;u<t.length;u++)t.charCodeAt(u)===10&&p.push(u+1)}return p}function l(u){let v=a(),y=0,A=v.length-1;for(;y<=A;){let S=y+A>>1;if(v[S]<=u){if(S===v.length-1||v[S+1]>u)return{line:S+1,column:u-v[S]+1};y=S+1}else A=S-1}return{line:1,column:u+1}}let d=null;function g(u){if(t.length<=1024*1024)return d||(d=t.split(/\r?\n/)),{lines:d,relativeTargetIdx:u-1};let v=a(),y=u-1,A=Math.max(0,y-30),S=Math.min(v.length-1,y+30),b=v[A],_=S+1<v.length?v[S+1]:t.length;return{lines:t.substring(b,_).split(/\r?\n/),relativeTargetIdx:y-A}}for(let u of s){u.pattern.lastIndex=0;let v;for(;(v=u.pattern.exec(t))!==null;){let y=v[1]!==void 0?v[1]:v[0],A=v[1]!==void 0?v[0].indexOf(v[1]):0,S=v.index+(A>=0?A:0),{line:b,column:_}=l(S),x=g(b),$=ue(x.lines,x.relativeTargetIdx),ae=ge(x.lines,x.relativeTargetIdx,e),R=he(u,y,r,$,e,ae);if(R.isSuppressed||u.minEntropy&&R.evidence.shannonEntropy<u.minEntropy)continue;let O=e;o&&e.startsWith(o)&&(O=e.substring(o.length).replace(/^[\\/]+/,""));let V=ve(u,R.confidence,r),z=be(u,y,O,b,$.inferredVariable),ce=Buffer.from(O).toString("hex").slice(0,8),de=`sec_${j(y)}_${ce}_${b}`,le=j(y),pe=U(y),Qe={id:de,fingerprint:le,type:u.name,provider:u.provider,file:O,fullPath:e,line:b,column:_,length:y.length,rawSecret:y,redactedSecret:pe,confidence:R.confidence,risk:V.tier,riskAssessment:V,evidence:R.evidence,remediation:z,status:"ACTIVE",detectedAt:new Date().toISOString(),signals:R.evidence.items.map(et=>et.description),exampleFix:z.replacementCode,entropy:R.evidence.shannonEntropy};c.push(Qe)}}let f=/["']([^"'\r\n]{2,80})["']\s*\+\s*["']([^"'\r\n]{8,120})["']/g,h;for(;(h=f.exec(t))!==null;){let u=h[1]+h[2],v=h.index;for(let y of s){y.pattern.lastIndex=0;let A;for(;(A=y.pattern.exec(u))!==null;){let S=A[1]||A[0],{line:b,column:_}=l(v),x=g(b),$=ue(x.lines,x.relativeTargetIdx),ae=ge(x.lines,x.relativeTargetIdx,e),R=he(y,S,r,$,e,ae);if(R.isSuppressed||y.minEntropy&&R.evidence.shannonEntropy<y.minEntropy)continue;let O=e;o&&e.startsWith(o)&&(O=e.substring(o.length).replace(/^[\\/]+/,""));let V=ve(y,R.confidence,r),z=be(y,S,O,b,$.inferredVariable);R.evidence.items.unshift({signal:"ADVERSARIAL_DEOBFUSCATION_RESOLVED",description:`Resolved split string concatenation: '${h[0]}'`,confidenceImpact:10});let ce=`sec_${j(S)}_${b}`,de=j(S),le=U(S);c.push({id:ce,fingerprint:de,type:y.name,provider:y.provider,file:O,fullPath:e,line:b,column:_,length:h[0].length,rawSecret:S,redactedSecret:le,confidence:Math.min(100,R.confidence+5),risk:V.tier,riskAssessment:V,evidence:R.evidence,remediation:z,status:"ACTIVE",detectedAt:new Date().toISOString(),signals:R.evidence.items.map(pe=>pe.description),exampleFix:z.replacementCode,entropy:R.evidence.shannonEntropy})}}}return ht(c)}function ht(t){let e=[];for(let n of t){let i=e.findIndex(s=>s.file===n.file&&s.line===n.line&&(s.rawSecret.includes(n.rawSecret)||n.rawSecret.includes(s.rawSecret)));if(i===-1)e.push(n);else{let s=e[i];(s.provider==="Generic Credential"&&n.provider!=="Generic Credential"||n.confidence>s.confidence)&&(e[i]=n)}}return e}var te=class{diagnosticCollection;currentFindings=new Map;ignoredFindings=new Set;onFindingsChangedEmitter=new w.EventEmitter;onFindingsChanged=this.onFindingsChangedEmitter.event;minEntropy;constructor(){this.diagnosticCollection=w.languages.createDiagnosticCollection("secret-leak-detector")}setMinEntropy(e){this.minEntropy=e}getDiagnosticCollection(){return this.diagnosticCollection}getAllFindings(){let e=[];for(let n of this.currentFindings.values())e.push(...n);return e}clear(){this.diagnosticCollection.clear(),this.currentFindings.clear(),this.onFindingsChangedEmitter.fire([])}ignoreFinding(e){this.ignoredFindings.add(e);for(let[n,i]of this.currentFindings.entries()){let s=i.filter(o=>o.id!==e);if(s.length!==i.length){this.currentFindings.set(n,s);let o=w.Uri.file(n),r=this.diagnosticCollection.get(o);if(r){let c=r.filter(p=>(typeof p.code=="object"?p.code?.value:p.code)!==e);this.diagnosticCollection.set(o,c)}}}this.onFindingsChangedEmitter.fire(this.getAllFindings())}setIgnoredFindings(e){this.ignoredFindings=new Set(e)}getIgnoredFindings(){return Array.from(this.ignoredFindings)}scanDocument(e){if(e.uri.scheme!=="file")return[];let n=e.getText(),i=w.workspace.getWorkspaceFolder(e.uri),o={workspaceRoot:i?i.uri.fsPath:void 0,minEntropyThreshold:this.minEntropy},c=Z(n,e.uri.fsPath,o).filter(a=>!this.ignoredFindings.has(a.id));this.currentFindings.set(e.uri.fsPath,c);let p=[];for(let a of c){let l=Math.max(0,a.line-1),d=Math.max(0,a.column-1),g=new w.Position(l,d),f=e.offsetAt(g),h=e.positionAt(f+a.length),u=new w.Range(g,h),v=w.DiagnosticSeverity.Warning;a.risk==="CRITICAL"||a.risk==="HIGH"?v=w.DiagnosticSeverity.Error:a.risk==="LOW"&&(v=w.DiagnosticSeverity.Information);let y=typeof a.remediation=="string"?a.remediation:a.remediation?.steps?.[0]||"Migrate to .env",A=new w.Diagnostic(u,`[Secret Leak Detector] ${a.type} detected! Confidence: ${a.confidence}%. ${y}`,v);A.code={value:a.id,target:w.Uri.parse("https://github.com/MokuLakshithReddy/Secret_Leak_Detector")},A.source="Secret Leak Detector",p.push(A)}return this.diagnosticCollection.set(e.uri,p),this.onFindingsChangedEmitter.fire(this.getAllFindings()),c}removeDocument(e){this.diagnosticCollection.delete(e),this.currentFindings.delete(e.fsPath),this.onFindingsChangedEmitter.fire(this.getAllFindings())}dispose(){this.diagnosticCollection.dispose(),this.onFindingsChangedEmitter.dispose()}};var E=T(require("vscode")),P=T(require("fs")),Y=T(require("path"));function vt(t,e){switch(Y.extname(t).toLowerCase()){case".py":return`os.environ.get("${e}")`;case".go":return`os.Getenv("${e}")`;case".rb":return`ENV['${e}']`;case".php":return`getenv('${e}')`;case".java":case".kt":return`System.getenv("${e}")`;case".rs":return`std::env::var("${e}").unwrap()`;case".sh":case".bash":case".zsh":return`"\${${e}}"`;case".yaml":case".yml":case".toml":case".env":return`\${${e}}`;case".js":case".jsx":case".ts":case".tsx":case".mjs":case".cjs":default:return`process.env.${e}`}}var H=class{static providedCodeActionKinds=[E.CodeActionKind.QuickFix];diagnosticProvider;constructor(e){this.diagnosticProvider=e}provideCodeActions(e,n,i){let s=[],o=i.diagnostics.filter(c=>c.source==="Secret Leak Detector");if(o.length===0)return s;let r=this.diagnosticProvider.getAllFindings();for(let c of o){let p=typeof c.code=="object"?c.code?.value:c.code,a=r.find(f=>f.id===p);if(!a||e.getText(c.range)!==a.rawSecret)continue;let d=this.createMoveToEnvAction(e,c.range,a);s.push(d);let g=new E.CodeAction("Ignore this finding (False Positive)",E.CodeActionKind.QuickFix);g.command={command:"secret-leak-detector.ignoreFinding",title:"Ignore Finding",arguments:[a.id]},s.push(g)}return s}createMoveToEnvAction(e,n,i){let s=new E.CodeAction(`\u{1F6E1}\uFE0F Move ${i.type} to .env and replace with environment variable`,E.CodeActionKind.QuickFix);return s.isPreferred=!0,s.command={command:"secret-leak-detector.remediateFinding",title:"Move to .env",arguments:[e.uri,n,i]},s}static async executeRemediation(e,n,i){let s=E.workspace.getWorkspaceFolder(e);if(!s){E.window.showErrorMessage("No workspace folder found to save .env file.");return}let o=await E.workspace.openTextDocument(e);if(o.getText(n)!==i.rawSecret){E.window.showErrorMessage("The secret at the target location has changed or was already removed.");return}let r=s.uri.fsPath,c=Y.join(r,".env"),p=i.remediation?.envVarName;p||(i.type.includes("AWS Access Key")?p="AWS_ACCESS_KEY_ID":i.type.includes("AWS Secret")?p="AWS_SECRET_ACCESS_KEY":i.type.includes("GitHub")?p="GITHUB_TOKEN":i.type.includes("OpenAI")?p="OPENAI_API_KEY":i.type.includes("Anthropic")?p="ANTHROPIC_API_KEY":i.type.includes("Stripe")?p="STRIPE_SECRET_KEY":i.type.includes("Slack")?p="SLACK_TOKEN":i.type.includes("Database")?p="DATABASE_URL":p=`${i.provider.replace(/[^a-zA-Z0-9]/g,"_").toUpperCase()}_API_KEY`);let a="",l=!1;if(P.existsSync(c)){l=!0;try{a=P.readFileSync(c,"utf8")}catch(b){E.window.showErrorMessage(`Failed to read .env file: ${b}`);return}}let{varName:d,isReused:g}=Be(a,p,i.rawSecret);try{Ke(r)}catch(b){E.window.showErrorMessage(`Failed to verify .gitignore security: ${b.message||b}`);return}let f=n,h=!1;if(n.start.character>0){let b=n.start.translate(0,-1),_=n.end.translate(0,1),x=o.getText(new E.Range(b,n.start)),$=o.getText(new E.Range(n.end,_));(x==='"'&&$==='"'||x==="'"&&$==="'")&&(f=new E.Range(b,_),h=!0)}let u=vt(e.fsPath,d),v=new E.WorkspaceEdit;if(v.replace(e,f,u),!await E.workspace.applyEdit(v)){E.window.showErrorMessage("Failed to modify source document. Remediation aborted with zero file alterations.");return}let A=ee(i.rawSecret),S=`${d}="${A}"
`;try{if(!g)if(!l)P.writeFileSync(c,S,{mode:384,encoding:"utf8"});else{let x=a.endsWith(`
`)||a.length===0?"":`
`;P.appendFileSync(c,`${x}${S}`,{mode:384,encoding:"utf8"})}let b=Y.join(r,".env.example"),_=`${d}=your_${d.toLowerCase()}_here
`;if(!P.existsSync(b)||!P.readFileSync(b,"utf8").includes(d)){let x=P.existsSync(b)?P.readFileSync(b,"utf8"):"",$=x.endsWith(`
`)||x.length===0?"":`
`;P.appendFileSync(b,`${$}${_}`,"utf8")}}catch(b){let _=new E.Range(f.start,f.start.translate(0,u.length)),x=new E.WorkspaceEdit;x.replace(e,_,h?`"${i.rawSecret}"`:i.rawSecret),await E.workspace.applyEdit(x),E.window.showErrorMessage(`Failed to write to .env: ${b}. Document edit was safely rolled back.`);return}E.window.showInformationMessage(`\u2705 Moved ${i.type} to .env (${d}) and verified .gitignore protection!`)}};var k=T(require("vscode")),ne=class{_onDidChangeTreeData=new k.EventEmitter;onDidChangeTreeData=this._onDidChangeTreeData.event;findings=[];updateFindings(e){this.findings=e,this._onDidChangeTreeData.fire()}getTreeItem(e){return e}getChildren(e){if(!e){if(this.findings.length===0){let s=new L("No Leaks Detected (Safe)",k.TreeItemCollapsibleState.None);return s.iconPath=new k.ThemeIcon("shield-check",new k.ThemeColor("testing.iconPassed")),s.description="Workspace is clean",Promise.resolve([s])}let n=["CRITICAL","HIGH","MEDIUM","LOW"],i=[];for(let s of n){let o=this.findings.filter(r=>r.risk===s).length;if(o>0){let r=new L(`${s} Risk (${o})`,k.TreeItemCollapsibleState.Expanded,s);s==="CRITICAL"?r.iconPath=new k.ThemeIcon("error",new k.ThemeColor("errorForeground")):s==="HIGH"?r.iconPath=new k.ThemeIcon("warning",new k.ThemeColor("editorWarning.foreground")):s==="MEDIUM"?r.iconPath=new k.ThemeIcon("info",new k.ThemeColor("editorInfo.foreground")):r.iconPath=new k.ThemeIcon("pass",new k.ThemeColor("testing.iconPassed")),i.push(r)}}return Promise.resolve(i)}if(e.contextValue){let n=e.contextValue,s=this.findings.filter(o=>o.risk===n).map(o=>{let r=new L(`${o.type}`,k.TreeItemCollapsibleState.None);return r.description=`${o.file}:${o.line}`,r.tooltip=new k.MarkdownString(`**${o.type}** (${o.provider})

- **Risk:** ${o.risk}
- **Confidence:** ${o.confidence}%
- **Entropy:** ${o.entropy} bits/char
- **Secret:** \`${o.redactedSecret}\`

*${o.remediation}*`),r.iconPath=new k.ThemeIcon("key"),r.command={command:"vscode.open",title:"Jump to Secret",arguments:[k.Uri.file(o.fullPath),{selection:new k.Range(o.line-1,o.column-1,o.line-1,o.column-1+o.length)}]},r});return Promise.resolve(s)}return Promise.resolve([])}},ie=class{_onDidChangeTreeData=new k.EventEmitter;onDidChangeTreeData=this._onDidChangeTreeData.event;findingsCount=0;isGit=!0;update(e,n){this.findingsCount=e,this.isGit=n,this._onDidChangeTreeData.fire()}getTreeItem(e){return e}getChildren(){let e=[],n=new L(this.findingsCount===0?"Status: Protected":`Status: ${this.findingsCount} Leaks Active`,k.TreeItemCollapsibleState.None);n.iconPath=new k.ThemeIcon(this.findingsCount===0?"check":"alert",this.findingsCount===0?new k.ThemeColor("testing.iconPassed"):new k.ThemeColor("errorForeground")),e.push(n);let i=new L("Run Full Workspace Scan",k.TreeItemCollapsibleState.None);i.iconPath=new k.ThemeIcon("search"),i.command={command:"secret-leak-detector.scanWorkspace",title:"Scan Workspace"},e.push(i);let s=new L("Check Git Staged Changes",k.TreeItemCollapsibleState.None);s.iconPath=new k.ThemeIcon("git-commit"),s.command={command:"secret-leak-detector.scanStaged",title:"Scan Staged Changes"},e.push(s);let o=new L("Open Interactive Dashboard",k.TreeItemCollapsibleState.None);o.iconPath=new k.ThemeIcon("dashboard"),o.command={command:"secret-leak-detector.openDashboard",title:"Open Dashboard"},e.push(o);let r=new L("Install Pre-Commit Hook",k.TreeItemCollapsibleState.None);return r.iconPath=new k.ThemeIcon("terminal"),r.command={command:"secret-leak-detector.installGitHook",title:"Install Hook"},e.push(r),Promise.resolve(e)}},L=class extends k.TreeItem{constructor(e,n,i){super(e,n),this.contextValue=i}};var I=T(require("vscode")),He=T(require("crypto"));function ye(t){let e=typeof t.remediation=="string"?t.remediation:t.remediation?.steps?.join("; ")||"Rotate and move to .env",n=t.exampleFix||t.remediation?.replacementCode||"";return{id:t.id,type:t.type,provider:t.provider,file:t.file,fullPath:t.fullPath,line:t.line,column:t.column,redactedSecret:t.redactedSecret,confidence:t.confidence,entropy:t.entropy??0,risk:t.risk,remediationText:e,exampleFix:n}}var B=class t{static currentPanel;static viewType="secretLeakDetectorDashboard";_panel;_extensionUri;_disposables=[];_findings=[];static createOrShow(e,n){let i=I.window.activeTextEditor?I.window.activeTextEditor.viewColumn:void 0;if(t.currentPanel){t.currentPanel._panel.reveal(i),t.currentPanel.updateFindings(n);return}let s=I.window.createWebviewPanel(t.viewType,"\u{1F510} Secret Leak Detector Dashboard",i||I.ViewColumn.One,{enableScripts:!0,retainContextWhenHidden:!0,localResourceRoots:[e]});t.currentPanel=new t(s,e,n)}constructor(e,n,i){this._panel=e,this._extensionUri=n,this._findings=i,this._update(),this._panel.onDidDispose(()=>this.dispose(),null,this._disposables),this._panel.webview.onDidReceiveMessage(async s=>{switch(s.command){case"scanWorkspace":I.commands.executeCommand("secret-leak-detector.scanWorkspace");return;case"scanStaged":I.commands.executeCommand("secret-leak-detector.scanStaged");return;case"installHook":I.commands.executeCommand("secret-leak-detector.installGitHook");return;case"openFile":if(s.file&&s.line){let o=await I.workspace.openTextDocument(I.Uri.file(s.file));await I.window.showTextDocument(o,{selection:new I.Range(s.line-1,0,s.line-1,0)})}return}},null,this._disposables)}updateFindings(e){this._findings=e;let n=this._findings.map(ye);this._panel.webview.postMessage({command:"updateData",findings:n})}dispose(){for(t.currentPanel=void 0,this._panel.dispose();this._disposables.length;){let e=this._disposables.pop();e&&e.dispose()}}_update(){this._panel.webview.html=this._getHtmlForWebview()}_getHtmlForWebview(){let e=He.randomBytes(16).toString("base64"),n=this._findings.map(ye),i=JSON.stringify(n).replace(/</g,"\\u003c");return`<!DOCTYPE html>
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
</html>`}};var Je=require("child_process"),Xe=require("util"),C=T(require("fs")),F=T(require("path"));var K=require("child_process"),Ge=require("util"),W=T(require("path"));var se=(0,Ge.promisify)(K.execFile),G=["-c","core.quotepath=false","--literal-pathspecs"];function We(t){return t.startsWith("R")||t.startsWith("C")}function Ve(t){return t.startsWith("D")}function bt(t){try{let e=(0,K.execFileSync)("git",["rev-parse","--show-toplevel"],{cwd:t,encoding:"utf8"}).trim();if(e)return W.resolve(e)}catch{}return t}async function yt(t){try{let{stdout:e}=await se("git",["rev-parse","--show-toplevel"],{cwd:t,encoding:"utf8"}),n=e.trim();if(n)return W.resolve(n)}catch{}return t}function ze(t){let e=bt(t),n;try{n=(0,K.execFileSync)("git",[...G,"diff","--cached","-z","--name-status"],{cwd:e,encoding:"utf8",maxBuffer:10*1024*1024})}catch(r){return{status:"ERROR",findings:[],error:`git diff --cached failed: ${r.message||String(r)}`}}let i=n.split("\0").filter(Boolean),s=[],o=0;for(let r=0;r<i.length;){let c=i[r],a=i[r+1],l=2;We(c)&&i[r+2]!==void 0&&(a=i[r+2],l=3),r+=l;let d=a.replace(/\\/g,"/");if(d==="/dev/null"||Ve(c))continue;let g;try{g=(0,K.execFileSync)("git",[...G,"show",`:${d}`],{cwd:e,encoding:"utf8",maxBuffer:10*1024*1024})}catch(u){s.push({type:"SCAN_ERROR",provider:"Internal",file:d,fullPath:W.join(e,a),line:0,column:0,rawSecret:"",redactedSecret:"",confidence:0,risk:"CRITICAL",signals:[`git show failed: ${u.message||String(u)}`],evidence:{score:0,items:[]},riskAssessment:{score:100,blastRadius:{level:"UNKNOWN",summary:"Staged blob unreadable \u2014 scan blocked"},factors:[]},remediation:{steps:[],envVarName:"",replacementCode:"",envFileSnippet:"",envExampleSnippet:"",gitHistoryPurgeCommand:"",diffPreview:""}});continue}let f=new Set;try{let u=(0,K.execFileSync)("git",[...G,"diff","--cached","-U0","--",d],{cwd:e,encoding:"utf8",maxBuffer:10485760}),v=/^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/gm,y;for(;(y=v.exec(u))!==null;){let A=parseInt(y[1],10),S=y[2]!==void 0?parseInt(y[2],10):1;for(let b=0;b<S;b++)f.add(A+b)}}catch(u){return{status:"ERROR",findings:s,error:`Could not determine staged diff for '${d}': ${u.message||String(u)}`,filesScanned:o}}if(f.size===0)continue;let h=Z(g,d,{workspaceRoot:e});for(let u of h)f.has(u.line)&&s.push(u);o++}return s.length>0?{status:"FINDINGS",findings:s,filesScanned:o}:{status:"CLEAN",findings:[],filesScanned:o}}async function Ue(t){let e=await yt(t),n;try{let{stdout:r}=await se("git",[...G,"diff","--cached","-z","--name-status"],{cwd:e,encoding:"utf8",maxBuffer:10485760});n=r}catch(r){return{status:"ERROR",findings:[],error:`git diff --cached failed: ${r.message||String(r)}`}}let i=n.split("\0").filter(Boolean),s=[],o=0;for(let r=0;r<i.length;){let c=i[r],a=i[r+1],l=2;We(c)&&i[r+2]!==void 0&&(a=i[r+2],l=3),r+=l;let d=a.replace(/\\/g,"/");if(d==="/dev/null"||Ve(c))continue;let g;try{let{stdout:u}=await se("git",[...G,"show",`:${d}`],{cwd:e,encoding:"utf8",maxBuffer:10485760});g=u}catch(u){s.push({type:"SCAN_ERROR",provider:"Internal",file:d,fullPath:W.join(e,a),line:0,column:0,rawSecret:"",redactedSecret:"",confidence:0,risk:"CRITICAL",signals:[`git show failed: ${u.message||String(u)}`],evidence:{score:0,items:[]},riskAssessment:{score:100,blastRadius:{level:"UNKNOWN",summary:"Staged blob unreadable \u2014 scan blocked"},factors:[]},remediation:{steps:[],envVarName:"",replacementCode:"",envFileSnippet:"",envExampleSnippet:"",gitHistoryPurgeCommand:"",diffPreview:""}});continue}let f=new Set;try{let{stdout:u}=await se("git",[...G,"diff","--cached","-U0","--",d],{cwd:e,encoding:"utf8",maxBuffer:10485760}),v=/^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/gm,y;for(;(y=v.exec(u))!==null;){let A=parseInt(y[1],10),S=y[2]!==void 0?parseInt(y[2],10):1;for(let b=0;b<S;b++)f.add(A+b)}}catch(u){return{status:"ERROR",findings:s,error:`Could not determine staged diff for '${d}': ${u.message||String(u)}`,filesScanned:o}}if(f.size===0)continue;let h=Z(g,d,{workspaceRoot:e});for(let u of h)f.has(u.line)&&s.push(u);o++}return s.length>0?{status:"FINDINGS",findings:s,filesScanned:o}:{status:"CLEAN",findings:[],filesScanned:o}}var je=["LOW","MEDIUM","HIGH","CRITICAL"],ke={LOW:1,MEDIUM:2,HIGH:3,CRITICAL:4},N="HIGH";function Ze(t,e=N){return(ke[t]||0)>=(ke[e]||ke.CRITICAL)}var oe="# [SLD_HOOK_MANAGED]";function Ye(t=N,e){let n=je.includes(t)?t:N,i=e?e.replace(/\\/g,"/"):"",s=i?`# Scanner pinned to bundled CLI path
if [ -f "${i}" ]; then
  node "${i}" scan --staged --fail-on "$SLD_FAIL_ON"
  SCAN_STATUS=$?
elif command -v secret-leak-detector >/dev/null 2>&1; then
  secret-leak-detector scan --staged --fail-on "$SLD_FAIL_ON"
  SCAN_STATUS=$?
else
  echo ""
  echo "\u274C COMMIT BLOCKED (fail-closed): Secret Leak Detector scanner is unavailable."
  echo "   Pinned CLI (${i}) not found and no global CLI available."
  echo "   Staged changes could not be verified secret-free, so the commit was refused."
  exit 1
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
  exit 1
fi`;return`#!/bin/sh
${oe}
# Secret Leak Detector Pre-Commit Hook
# Intercepts git commit and blocks unredacted credentials before they leave the machine.
#
# Severity policy (single source of truth: src/core/policy.ts):
#   Blocks findings at ${n} and above (LOW < MEDIUM < HIGH < CRITICAL).
#   Lower tiers are reported but do not block.
#
# Fail-closed: if the scanner cannot be executed, the commit is BLOCKED.
SLD_FAIL_ON="${n}"

echo "\u{1F510} [Secret Leak Detector] Inspecting staged changes for credentials..."

${s}

if [ "$SCAN_STATUS" -eq 1 ]; then
  echo ""
  echo "\u274C COMMIT BLOCKED: Secret Leak Detector detected credentials in staged files!"
  echo "Please rotate the secret or migrate it to an environment variable."
  exit 1
elif [ "$SCAN_STATUS" -ne 0 ]; then
  echo ""
  echo "\u274C COMMIT BLOCKED (fail-closed): Scanner exited with error ($SCAN_STATUS)."
  exit 1
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
`}var qe=(0,Xe.promisify)(Je.execFile),re=class{workspaceRoot;cliPath;constructor(e,n){if(this.workspaceRoot=e,n&&C.existsSync(n))this.cliPath=n;else{let i=[F.resolve(__dirname,"cli.js"),F.resolve(__dirname,"../../dist/cli.js"),F.resolve(process.cwd(),"dist/cli.js")];this.cliPath=i.find(s=>C.existsSync(s))}}async isGitRepo(){try{return await qe("git",["rev-parse","--is-inside-work-tree"],{cwd:this.workspaceRoot}),!0}catch{return!1}}async scanStagedChanges(){return Ue(this.workspaceRoot)}scanStagedChangesSync(){return ze(this.workspaceRoot)}formatTerminalBlockedMessage(e){let i=e.filter(p=>p.risk==="CRITICAL")[0]||e[0],s=typeof i.remediation=="string"?i.remediation:i.remediation?.steps?.join(`
`)||"Rotate and move to .env",o=i.evidence?.items?.map(p=>`  - [${p.confidenceImpact>=0?"+":""}${p.confidenceImpact}] ${p.description}`).join(`
`)||i.signals?.map(p=>`  - ${p}`).join(`
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
`}async resolveHooksDir(){try{let{stdout:e}=await qe("git",["rev-parse","--git-path","hooks"],{cwd:this.workspaceRoot}),n=e.trim();return F.isAbsolute(n)?n:F.resolve(this.workspaceRoot,n)}catch{return F.join(this.workspaceRoot,".git","hooks")}}async installPreCommitHook(e){if(!await this.isGitRepo())return{success:!1,message:"Workspace is not a Git repository."};let n=await this.resolveHooksDir();if(!C.existsSync(n))try{C.mkdirSync(n,{recursive:!0})}catch(l){return{success:!1,message:`Could not create hooks directory (${n}): ${l}`}}let i=F.join(n,"pre-commit"),s=Date.now(),o=F.join(n,`pre-commit.sld-backup.${s}`),r=F.join(n,"pre-commit.sld-backup.latest"),c=oe;if(C.existsSync(i))try{let l=C.readFileSync(i,"utf8");l.includes(c)||(C.writeFileSync(o,l,{mode:493}),C.writeFileSync(r,o,"utf8"))}catch(l){return{success:!1,message:`Could not backup existing hook: ${l}`}}let p=e||this.cliPath,a=Ye(N,p);try{return C.writeFileSync(i,a,{mode:493}),{success:!0,message:`Pre-commit hook successfully installed to ${i}`}}catch(l){return{success:!1,message:`Failed to write hook file: ${l}`}}}async uninstallPreCommitHook(){let e=await this.resolveHooksDir(),n=F.join(e,"pre-commit"),i=F.join(e,"pre-commit.sld-backup.latest");if(!C.existsSync(n))return{success:!0,message:"No pre-commit hook found to uninstall."};try{if(!C.readFileSync(n,"utf8").includes(oe))return{success:!1,message:"Existing pre-commit hook is not managed by Secret Leak Detector; refusing to delete user hook."};if(C.existsSync(i)){let o=C.readFileSync(i,"utf8").trim();if(o&&C.existsSync(o))return C.copyFileSync(o,n),C.unlinkSync(o),C.unlinkSync(i),{success:!0,message:"Uninstalled SLD hook and restored original pre-commit hook."}}return C.unlinkSync(n),{success:!0,message:"Removed Secret Leak Detector pre-commit hook."}}catch(s){return{success:!1,message:`Failed to uninstall hook: ${s.message}`}}}};var D;function kt(t){D=m.window.createOutputChannel("Secret Leak Detector"),t.subscriptions.push(D),D.appendLine("\u{1F510} [Secret Leak Detector] Extension activated.");let e=new te;t.subscriptions.push(e),t.subscriptions.push(m.languages.registerCodeActionsProvider({scheme:"file"},new H(e),{providedCodeActionKinds:H.providedCodeActionKinds}));let n=new ne,i=new ie;m.window.registerTreeDataProvider("secret-leak-detector.findingsView",n),m.window.registerTreeDataProvider("secret-leak-detector.overviewView",i);let s=m.workspace.workspaceFolders?.[0],o=s?s.uri.fsPath:process.cwd(),r=new re(o);e.onFindingsChanged(a=>{n.updateFindings(a),i.update(a.length,!0),B.currentPanel&&B.currentPanel.updateFindings(a)});function c(){let l=m.workspace.getConfiguration("secretLeakDetector").get("minEntropy");e.setMinEntropy(typeof l=="number"&&l>0?l:void 0);let d=t.workspaceState.get("ignoredFindings",[]);e.setIgnoredFindings(d)}c(),t.subscriptions.push(m.workspace.onDidChangeConfiguration(a=>{a.affectsConfiguration("secretLeakDetector")&&(c(),m.window.activeTextEditor&&e.scanDocument(m.window.activeTextEditor.document))})),m.window.activeTextEditor&&e.scanDocument(m.window.activeTextEditor.document),t.subscriptions.push(m.workspace.onDidSaveTextDocument(a=>{m.workspace.getConfiguration("secretLeakDetector").get("enableRealtimeScanning",!0)&&e.scanDocument(a)})),t.subscriptions.push(m.workspace.onDidOpenTextDocument(a=>{m.workspace.getConfiguration("secretLeakDetector").get("enableRealtimeScanning",!0)&&e.scanDocument(a)}));let p;t.subscriptions.push(m.workspace.onDidChangeTextDocument(a=>{m.workspace.getConfiguration("secretLeakDetector").get("enableRealtimeScanning",!0)&&(p&&clearTimeout(p),p=setTimeout(()=>{e.scanDocument(a.document)},350))})),t.subscriptions.push(m.workspace.onDidDeleteFiles(a=>{a.files.forEach(l=>e.removeDocument(l))})),t.subscriptions.push(m.commands.registerCommand("secret-leak-detector.scanWorkspace",async()=>{await m.window.withProgress({location:m.ProgressLocation.Notification,title:"\u{1F510} Scanning workspace for secret leaks...",cancellable:!1},async a=>{let d=`{${config.get("excludeGlobs",[]).join(",")}}`,g=1e3,f=await m.workspace.findFiles("**/*",d,g),h=[],u=0,v=0;for(let S of f)try{if((await m.workspace.fs.stat(S)).size>5*1024*1024){v++;continue}let _=await m.workspace.openTextDocument(S),x=e.scanDocument(_);h.push(...x),u++}catch{v++}let y=f.length>=g,A=`Scanned ${u} files.`;if(y&&(A+=` \u26A0\uFE0F Scan was capped at ${g} files.`),v>0&&(A+=` (${v} large or binary files skipped)`),h.length===0)m.window.showInformationMessage(`\u2705 Scan complete: ${A} No secrets or credentials detected!`);else{let S=h.filter(b=>b.risk==="CRITICAL").length;m.window.showErrorMessage(`\u{1F6A8} Found ${h.length} leaked secret(s) (${S} Critical)! ${A}`,"Open Dashboard","View Findings").then(b=>{b==="Open Dashboard"?m.commands.executeCommand("secret-leak-detector.openDashboard"):b==="View Findings"&&m.commands.executeCommand("workbench.view.extension.secret-leak-detector-sidebar")})}})})),t.subscriptions.push(m.commands.registerCommand("secret-leak-detector.scanStaged",async()=>{D.clear(),D.appendLine("\u{1F510} [Secret Leak Detector] Scanning Git staged changes..."),D.show(!0);let a=config.get("blockGitCommits",!0),l=await r.scanStagedChanges();if(l.status==="ERROR"){D.appendLine(`\u274C [Secret Leak Detector] Scan error: ${l.error}`),a?m.window.showErrorMessage(`\u274C COMMIT GATE BLOCKED: Git security scan failed (${l.error}). Failing closed for safety.`,"View Output"):m.window.showWarningMessage(`\u26A0\uFE0F Git scan encountered an error: ${l.error}`);return}if(l.status==="CLEAN"){D.appendLine("\u2705 All staged changes are clean! No credentials detected."),m.window.showInformationMessage("\u2705 Git staged changes are safe to commit.");return}let d=l.findings,g=d.filter(v=>Ze(v.risk,N)),f=r.formatTerminalBlockedMessage(g.length>0?g:d);D.appendLine(f);let u=a&&g.length>0?`\u274C COMMIT BLOCKED: ${g.length} secret(s) at or above ${N} detected in staged changes!`:`\u26A0\uFE0F WARNING: ${d.length} secret(s) detected in staged changes (none block at the ${N} threshold).`;m.window.showErrorMessage(u,"Open Dashboard","View Output").then(v=>{v==="Open Dashboard"&&B.createOrShow(t.extensionUri,d)})})),t.subscriptions.push(m.commands.registerCommand("secret-leak-detector.openDashboard",()=>{B.createOrShow(t.extensionUri,e.getAllFindings())})),t.subscriptions.push(m.commands.registerCommand("secret-leak-detector.installGitHook",async()=>{let a=await r.installPreCommitHook();a.success?m.window.showInformationMessage(`\u{1F6E1}\uFE0F ${a.message}`):m.window.showErrorMessage(`Failed to install hook: ${a.message}`)})),t.subscriptions.push(m.commands.registerCommand("secret-leak-detector.uninstallGitHook",async()=>{let a=await r.uninstallPreCommitHook();a.success?m.window.showInformationMessage(`\u{1F6E1}\uFE0F ${a.message}`):m.window.showErrorMessage(`Failed to uninstall hook: ${a.message}`)})),t.subscriptions.push(m.commands.registerCommand("secret-leak-detector.ignoreFinding",async a=>{let l=a;if(!l){let g=e.getAllFindings();if(g.length===0){m.window.showInformationMessage("No active findings to ignore.");return}let f=await m.window.showQuickPick(g.map(h=>({label:`${h.type} (${h.file}:${h.line})`,description:h.redactedSecret,id:h.id})),{placeHolder:"Select a finding to ignore (suppress as false-positive)"});if(!f)return;l=f.id}e.ignoreFinding(l);let d=e.getIgnoredFindings();await t.workspaceState.update("ignoredFindings",d),m.window.showInformationMessage("\u{1F6E1}\uFE0F Finding marked as false-positive and suppressed.")})),t.subscriptions.push(m.commands.registerCommand("secret-leak-detector.remediateFinding",async(a,l,d)=>{await H.executeRemediation(a,l,d)})),t.subscriptions.push(m.commands.registerCommand("secret-leak-detector.clearFindings",()=>{e.clear(),m.window.showInformationMessage("Secret Leak Detector: All findings cleared.")})),r.isGitRepo().then(a=>{i.update(0,a)})}function St(){D&&D.dispose()}0&&(module.exports={activate,deactivate});
