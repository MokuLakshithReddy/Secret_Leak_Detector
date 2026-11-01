"use strict";var at=Object.create;var ie=Object.defineProperty;var ct=Object.getOwnPropertyDescriptor;var dt=Object.getOwnPropertyNames;var lt=Object.getPrototypeOf,pt=Object.prototype.hasOwnProperty;var ut=(t,e)=>{for(var i in e)ie(t,i,{get:e[i],enumerable:!0})},xe=(t,e,i,n)=>{if(e&&typeof e=="object"||typeof e=="function")for(let s of dt(e))!pt.call(t,s)&&s!==i&&ie(t,s,{get:()=>e[s],enumerable:!(n=ct(e,s))||n.enumerable});return t};var I=(t,e,i)=>(i=t!=null?at(lt(t)):{},xe(e||!t||!t.__esModule?ie(i,"default",{value:t,enumerable:!0}):i,t)),mt=t=>xe(ie({},"__esModule",{value:!0}),t);var Tt={};ut(Tt,{activate:()=>wt,deactivate:()=>Rt});module.exports=mt(Tt);var f=I(require("vscode")),ot=I(require("path")),rt=I(require("fs"));var w=I(require("vscode"));var V=I(require("path")),Ue=I(require("crypto"));var Ie=[{id:"aws-access-key",name:"AWS Access Key ID",provider:"Amazon Web Services",pattern:/\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b/g,baseConfidence:98,baseRiskWeight:95,signals:["AWS IAM standard 20-character key prefix (AKIA/ASIA/ABIA/ACCA)","Deterministic uppercase alphanumeric structure","Direct cloud resource control & hijacking capability"],suggestedEnvName:()=>"AWS_ACCESS_KEY_ID",remediationInstructions:["Revoke the exposed Access Key ID immediately in AWS IAM Management Console.","Check AWS CloudTrail logs for unauthorized API calls originated by this key.","Transition to IAM Roles for Amazon EC2 or AWS IAM Identity Center (SSO).","Never store access keys in source code; use AWS_ACCESS_KEY_ID environment variable."]},{id:"aws-secret-key",name:"AWS Secret Access Key",provider:"Amazon Web Services",pattern:/["']?(?:aws_secret_access_key|aws_secret_key|secret_access_key)["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?(?:[\s\r\n;,)]|$)/gi,baseConfidence:94,baseRiskWeight:95,minEntropy:4.1,signals:["Contextual AWS credential parameter match","High-entropy 40-character Base64 payload","Pairs with AWS Access Key for root/IAM API authentication"],suggestedEnvName:()=>"AWS_SECRET_ACCESS_KEY",remediationInstructions:["Rotate the key pair immediately in the AWS IAM Console.","Audit AWS KMS and S3 bucket accesses during exposure window.","Store secrets in AWS Secrets Manager or Parameter Store."]},{id:"github-pat",name:"GitHub Personal Access Token",provider:"GitHub",pattern:/\b(gh[pousr]_[A-Za-z0-9_]{36,255}|github_pat_[A-Za-z0-9_]{82})\b/g,baseConfidence:99,baseRiskWeight:95,signals:["Official GitHub token format prefix (ghp_, gho_, ghu_, ghs_, github_pat_)","Deterministic token structure and length","Permits repository code modification, workflow execution, or release poisoning"],suggestedEnvName:()=>"GITHUB_TOKEN",remediationInstructions:["Revoke token immediately at https://github.com/settings/tokens.","Check GitHub Security Audit Log for unauthorized repository clones or writes.","Use GitHub fine-grained PATs with scoped repository permissions.","Use GitHub Actions secrets rather than personal tokens for CI/CD."]},{id:"google-api-key",name:"Google Cloud / Gemini API Key",provider:"Google Cloud",pattern:/\b(AIza[0-9A-Za-z_-]{34,35})\b/g,baseConfidence:96,baseRiskWeight:90,minEntropy:3.5,signals:["Google standard AIza service key signature","Fixed 39-character alphanumeric structure","Access to Google Cloud Platform APIs and billing services"],suggestedEnvName:()=>"GEMINI_API_KEY",remediationInstructions:["Restrict or delete the API key in Google Cloud Console Credentials page.","Apply API restrictions (e.g. restrict solely to Generative Language API).","Apply HTTP referrer or IP address restrictions.","Store in GEMINI_API_KEY environment variable."]},{id:"openai-api-key",name:"OpenAI API Key",provider:"OpenAI",pattern:/\b(sk-(?:proj|admin|svcacct)-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{20,48})\b/g,baseConfidence:97,baseRiskWeight:92,minEntropy:4,signals:["OpenAI official secret prefix (sk-proj- or sk-)","High Shannon entropy key payload","Direct account credit exhaustion and model theft risk"],suggestedEnvName:()=>"OPENAI_API_KEY",remediationInstructions:["Revoke key at https://platform.openai.com/api-keys.","Verify credit consumption in OpenAI usage dashboard.","Inject credentials using OPENAI_API_KEY environment variable."]},{id:"anthropic-api-key",name:"Anthropic Claude API Key",provider:"Anthropic",pattern:/\b(sk-ant-[A-Za-z0-9_-]{30,})\b/g,baseConfidence:98,baseRiskWeight:92,minEntropy:3.8,signals:["Anthropic official secret token signature (sk-ant-)","High entropy cryptographic token payload","Direct Claude model API billing access"],suggestedEnvName:()=>"ANTHROPIC_API_KEY",remediationInstructions:["Revoke the API key in Anthropic Console.","Generate replacement key with spend limit configured.","Inject via ANTHROPIC_API_KEY environment variable."]},{id:"huggingface-token",name:"Hugging Face Access Token",provider:"Hugging Face",pattern:/\b(hf_[A-Za-z0-9]{34})\b/g,baseConfidence:98,baseRiskWeight:88,minEntropy:3.8,signals:["Hugging Face user access token format (hf_ prefix + 34 chars)","Grants access to gated AI models, private repositories, and inference endpoints"],suggestedEnvName:()=>"HF_TOKEN",remediationInstructions:["Revoke token immediately at https://huggingface.co/settings/tokens.","Audit access logs for unauthorized model downloads.","Inject credentials using the HF_TOKEN environment variable."]},{id:"stripe-secret-key",name:"Stripe Secret Key",provider:"Stripe",pattern:/\b((?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,100})\b/g,baseConfidence:97,baseRiskWeight:96,signals:["Stripe signature prefix (sk_live / rk_live / sk_test)","Financial transaction and customer credit card access","High financial liability and compliance breach"],suggestedEnvName:()=>"STRIPE_SECRET_KEY",remediationInstructions:["Roll API key immediately in Stripe Dashboard > Developers > API keys.","Audit recent transactions and payout bank account modifications.","Never bundle Stripe secret keys in frontend or mobile client builds."]},{id:"slack-bot-token",name:"Slack OAuth / Bot Token",provider:"Slack",pattern:/\b(xox[baprs]-[0-9A-Za-z-]{10,72})\b/g,baseConfidence:95,baseRiskWeight:82,signals:["Slack OAuth bot/user prefix (xoxb/xoxp/xoxa)","Internal company communications and workspace access"],suggestedEnvName:()=>"SLACK_BOT_TOKEN",remediationInstructions:["Revoke token in api.slack.com/apps.","Re-install app with minimal necessary OAuth scopes."]},{id:"slack-webhook",name:"Slack Incoming Webhook URL",provider:"Slack",pattern:/(https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9_]{8,12}\/B[A-Z0-9_]{8,12}\/[A-Za-z0-9_]{24})/g,baseConfidence:98,baseRiskWeight:78,signals:["Slack Incoming Webhook URL structure","Enables unauthorized message spoofing and channel phishing"],suggestedEnvName:()=>"SLACK_WEBHOOK_URL",remediationInstructions:["Delete the exposed webhook URL in Slack App settings.","Generate a new webhook URL and store in SLACK_WEBHOOK_URL."]},{id:"azure-storage-key",name:"Azure Shared Storage Key",provider:"Microsoft Azure",pattern:/["']?(?:AccountKey|azure_secret|azure_key)["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{86,88}==)(?:["';,\s\r\n)]|$)/gi,baseConfidence:93,baseRiskWeight:90,minEntropy:4.2,signals:["Azure storage account key signature (86-88 chars base64 with == padding)","Full administrative access to Azure Blob/Queue/Table storage"],suggestedEnvName:()=>"AZURE_STORAGE_KEY",remediationInstructions:["Regenerate storage key in Azure Portal.","Adopt Azure Managed Identity or Microsoft Entra ID authentication instead."]},{id:"private-key",name:"Cryptographic Private Key (PEM)",provider:"Cryptography",pattern:/(-----BEGIN (?:[A-Z0-9_-]+ )*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END (?:[A-Z0-9_-]+ )*PRIVATE KEY(?: BLOCK)?-----)/g,baseConfidence:100,baseRiskWeight:100,signals:["Standard PEM container header and footer","Unencrypted cryptographic private key","Total server impersonation, SSH compromise, or TLS decryption risk"],suggestedEnvName:()=>"PRIVATE_KEY_PATH",remediationInstructions:["Immediately decommission this private key pair.","Remove public key counterpart from all servers authorized_keys.","Never commit private keys to version control; use SSH agents or secret vaults."]},{id:"database-url",name:"Database Connection String with Credentials",provider:"Database",pattern:/\b((?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis):\/\/[^:\s'"]+:([^\s'"]+)@([a-zA-Z0-9_.-]+\.[a-zA-Z0-9_.-]+|localhost|127\.0\.0\.1|\[[0-9a-fA-F:]+\])(?::[0-9]+)?(?:\/[^\s'"`;]*)?)/gi,baseConfidence:92,baseRiskWeight:88,minEntropy:3.2,signals:["Database connection URL containing embedded user:password credentials","Direct data exfiltration, deletion, or ransomware risk"],suggestedEnvName:()=>"DATABASE_URL",remediationInstructions:["Rotate the database user password immediately on the database server.","Migrate connection string to DATABASE_URL environment variable.","Enable SSL/TLS requirement and VPC network access controls."]},{id:"jwt-token",name:"JSON Web Token (JWT)",provider:"Auth / Identity",pattern:/\b(ey[A-Za-z0-9_-]{15,}\.ey[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{10,})\b/g,baseConfidence:88,baseRiskWeight:75,minEntropy:4.1,signals:["Header.Payload.Signature Base64 tripartite JWT structure","Authentication session hijacking and privilege escalation"],suggestedEnvName:t=>t?.toUpperCase()||"AUTH_TOKEN",remediationInstructions:["Invalidate active sessions / revoke refresh token family in identity provider.","Never hardcode tokens in client or backend source repositories."]},{id:"gitlab-pat",name:"GitLab Personal Access Token",provider:"GitLab",pattern:/\b(glpat-[0-9a-zA-Z_-]{20,40})\b/g,baseConfidence:98,baseRiskWeight:90,signals:["GitLab personal access token prefix (glpat-)","Repository read/write and CI/CD control"],suggestedEnvName:()=>"GITLAB_TOKEN",remediationInstructions:["Revoke token in GitLab User Settings > Access Tokens.","Store in GITLAB_TOKEN environment variable."]},{id:"npm-access-token",name:"npm Access Token",provider:"npm",pattern:/\b(npm_[A-Za-z0-9]{36})\b/g,baseConfidence:99,baseRiskWeight:92,signals:["npm official access token prefix (npm_)","Package publication and account takeover capability"],suggestedEnvName:()=>"NPM_TOKEN",remediationInstructions:["Revoke token immediately at https://www.npmjs.com/settings/tokens.","Store in NPM_TOKEN environment variable."]},{id:"sendgrid-api-key",name:"SendGrid API Key",provider:"SendGrid",pattern:/\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b/g,baseConfidence:99,baseRiskWeight:85,signals:["SendGrid standard tripartite API key (SG.<22>.<43>)","Email spoofing and communication channel hijacking risk"],suggestedEnvName:()=>"SENDGRID_API_KEY",remediationInstructions:["Revoke key in SendGrid dashboard Settings > API Keys.","Store in SENDGRID_API_KEY environment variable."]},{id:"twilio-api-key",name:"Twilio Auth Token / API Secret",provider:"Twilio",pattern:/["']?(?:twilio[a-z0-9_-]*(?:auth_?token|api_?secret|secret)|(?:auth_?token|api_?secret))\s*[:=]\s*["']?([0-9a-fA-F]{32})["']?(?:[\s\r\n;,)]|$)/gi,baseConfidence:95,baseRiskWeight:90,minEntropy:3.5,signals:["Twilio Auth Token or API Secret assignment","32-character hexadecimal secret token","Telephony API and SMS billing access"],suggestedEnvName:()=>"TWILIO_AUTH_TOKEN",remediationInstructions:["Rotate token in Twilio Console.","Store in TWILIO_AUTH_TOKEN environment variable."]},{id:"password-assignment",name:"Password in Source Code",provider:"Generic Credential",pattern:/["']?(?:password|passwd|pwd|db_password|db_pass)["']?\s*[:=]\s*["'](?!(?:password|passwordRequired|required|required_field|true|false|null|undefined|string|default|changeme|placeholder|example|admin|test)\b)([^"'\r\n\s]{8,64})["']/gi,baseConfidence:82,baseRiskWeight:80,minEntropy:2.8,signals:["Hard-coded password assignment","Credential exposure in plain text"],suggestedEnvName:()=>"PASSWORD",remediationInstructions:["Rotate password immediately.","Store password in an environment variable or secrets manager.","Never commit plain passwords to version control."]},{id:"generic-api-key",name:"Generic API Secret Assignment",provider:"Generic Credential",pattern:/["']?(?:api_?key|secret_?key|auth_?token|client_?secret|access_?token|private_?key)["']?\s*[:=]\s*["']?(?!(?:process\.env|import\.meta\.env|os\.environ|ENV)\b)([A-Za-z0-9_.~/+=]{20,90})["']?(?:[\s\r\n;,)]|$)/gi,baseConfidence:80,baseRiskWeight:70,minEntropy:3.5,signals:["Sensitive identifier keyword assignment","High Shannon entropy string literal"],suggestedEnvName:t=>t?t.toUpperCase():"API_KEY",remediationInstructions:["Identify corresponding API provider and rotate credential.","Migrate credential to local .env file (ensure .env is in .gitignore)."]}];var D=I(require("path")),gt=[/api[_-]?key/i,/secret[_-]?key/i,/access[_-]?token/i,/auth[_-]?token/i,/private[_-]?key/i,/client[_-]?secret/i,/password/i,/credential/i,/session[_-]?token/i,/bearer/i,/aws[_-]?(?:access|secret)/i,/stripe[_-]?(?:secret|key)/i,/github[_-]?(?:token|pat)/i,/slack[_-]?token/i,/db[_-]?pass(?:word)?/i],ft=[/placeholder/i,/mock/i,/dummy/i,/fake/i,/sample/i,/test[_-]?(?:key|token|id)/i,/demo/i,/insert[_-]?here/i];function ht(t,e){if(e){let i=D.relative(e,t);if(!i.startsWith("..")&&!D.isAbsolute(i))return i.replace(/\\/g,"/")}return D.isAbsolute(t)?D.basename(t):t.replace(/\\/g,"/")}function we(t,e){let i=ht(t,e).toLowerCase(),n=D.basename(t).toLowerCase(),s=D.extname(t).toLowerCase(),o=/(?:^|\/)(?:tests?|specs?|__tests__|__mocks__|fixtures|mocks)\//i.test(i)||/[._-](?:test|spec)\.[a-z0-9]+$/i.test(n)||/^(?:test|spec)\.[a-z0-9]+$/i.test(n),r=/(?:^|\/)(?:docs|doc|documentation|tutorials|guides)\/|readme\.md|contributing\.md|changelog\.md/i.test(i),c=/(?:^|\/)(?:example|sample|\.example|\.sample)/i.test(i)||/[._-](?:example|sample)\.[a-z0-9]+$/i.test(n),d=/^\.env(?:\.[a-z0-9]+)?$/.test(n)||/(?:^|\/)(?:config|settings|k8s|helm|deploy|tfvars)\//i.test(i)||/(?:^|[._-])(?:config|settings|secret|credential|database|deploy)\.[a-z0-9]+$/i.test(n)||[".env",".yaml",".yml",".json",".toml",".ini",".tf"].includes(s),l=/^\.env/.test(n)||/(?:secret|credential|id_rsa|private_key|keypair|auth_config)/i.test(n);return{fileExtension:s,isConfig:d,isTest:o,isDoc:r,isSensitiveName:l,isExampleOrSample:c}}function fe(t,e){let i=t[e]||"",n=[];for(let h=Math.max(0,e-3);h<e;h++)n.push(t[h]);let s=[];for(let h=e+1;h<Math.min(t.length,e+4);h++)s.push(t[h]);let o,r=i.match(/(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*[:=]/),c=i.match(/["']?([a-zA-Z0-9_$-]+)["']?\s*[:=]/);r?o=r[1]:c&&(o=c[1]);let d=o?gt.some(h=>h.test(o)):!1,l=o?ft.some(h=>h.test(o)):!1,m=/[:=]/.test(i),a=/(?:process\.env|os\.environ|dotenv|config|getenv)/i.test(i),u=/(?:authorization|bearer|x-api-key)/i.test(i),g=/^\s*(?:\/\/|#|\/\*|\*|--)/.test(i);return{inferredVariable:o,isSensitiveIdentifier:d,isBenignIdentifier:l,isAssignment:m,isEnvOrConfigAccess:a,isHeaderOrBearer:u,isInComment:g,surroundingBefore:n,matchedLine:i,surroundingAfter:s}}var se=/(?:api_?key|secret|token|password|auth|credential|access_?key|private_?key)/i,Re=/(?:console\.(?:log|warn|error|info|debug)|logger\.|print\(|logging\.)/i,oe=null;try{oe=require("typescript")}catch{oe=null}function he(t,e,i){let n=t[e]||"";if(oe&&(!i||/\.[jt]sx?$|\.m[jt]s$|\.c[jt]s$/i.test(i))){let o,r;if(t.length>60){let d=Math.max(0,e-30),l=Math.min(t.length,e+30);o=t.slice(d,l).join(`
`),r=e-d}else o=t.join(`
`),r=e;let c=vt(o,r);if(c)return c}return bt(n)}function vt(t,e){try{let l=function(m){if(!d&&!(m.pos>c||m.end<r)&&(n.forEachChild(m,l),!d)){if(m.kind===n.SyntaxKind.BinaryExpression&&(m.operatorToken.kind===n.SyntaxKind.BarBarToken||m.operatorToken.kind===n.SyntaxKind.QuestionQuestionToken)){let a=m.left.getText(s);if(a.includes("process.env")||a.includes("env")||a.toLowerCase().includes("key")){d={variablePath:a,isSensitiveProperty:se.test(a),isEnvFallback:!0,isAuthorizationHeader:!1,isLoggingCall:!1,scopeType:"ENV_FALLBACK"};return}}if(m.kind===n.SyntaxKind.PropertyAssignment){let a=m.name.getText(s),u=a,g=m.parent;for(;g;)g.kind===n.SyntaxKind.PropertyAssignment&&g.name?u=`${g.name.getText(s)}.${u}`:g.kind===n.SyntaxKind.VariableDeclaration&&g.name&&(u=`${g.name.getText(s)}.${u}`),g=g.parent;let h=se.test(u),p=/authorization|bearer|x-api-key/i.test(a);d={variablePath:u,isSensitiveProperty:h,isEnvFallback:!1,isAuthorizationHeader:p,isLoggingCall:!1,scopeType:p?"HEADER":"OBJECT_PROPERTY"};return}if(m.kind===n.SyntaxKind.CallExpression){let a=m.expression.getText(s);if(Re.test(a)){d={variablePath:a,isSensitiveProperty:!1,isEnvFallback:!1,isAuthorizationHeader:!1,isLoggingCall:!0,scopeType:"FUNCTION_ARG"};return}}if(m.kind===n.SyntaxKind.VariableDeclaration){let a=m.name.getText(s);d={variablePath:a,isSensitiveProperty:se.test(a),isEnvFallback:!1,isAuthorizationHeader:!1,isLoggingCall:!1,scopeType:"VARIABLE_DECLARATION"};return}}};var i=l;let n=oe,s=n.createSourceFile("eval_target.tsx",t,n.ScriptTarget.Latest,!0,n.ScriptKind.TSX),o=s.getLineStarts();if(e>=o.length)return null;let r=o[e],c=e+1<o.length?o[e+1]-1:t.length,d=null;return l(s),d}catch{return null}}function bt(t){let e=Re.test(t),i=/(?:process\.env\.[A-Za-z0-9_]+|os\.(?:getenv|environ\.get)\([^)]+\))\s*(?:\|\||\?\?)\s*["'][^"']+["']/.test(t),n=/(?:authorization|x-api-key|bearer)\s*[:=]/i.test(t),s=t.match(/([a-zA-Z0-9_$.]+)\s*[:=]\s*["'][^"']+["']/)||t.match(/["']([a-zA-Z0-9_.]+)["']\s*:\s*["'][^"']+["']/),o,r=!1;s&&(o=s[1],r=se.test(o));let c="UNKNOWN";return i?c="ENV_FALLBACK":n?c="HEADER":o&&o.includes(".")?c="OBJECT_PROPERTY":o?c="VARIABLE_DECLARATION":e&&(c="FUNCTION_ARG"),{variablePath:o,isSensitiveProperty:r,isEnvFallback:i,isAuthorizationHeader:n,isLoggingCall:e,scopeType:c}}function ve(t){if(!t||t.length===0)return 0;let e={};for(let s of t)e[s]=(e[s]||0)+1;let i=0,n=t.length;for(let s in e){let o=e[s]/n;i-=o*Math.log2(o)}return Math.round(i*100)/100}function be(t){return/^[0-9a-fA-F]+$/.test(t)?{setName:"HEX",baseSize:16}:/^[A-Za-z0-9+/=_-]+$/.test(t)?{setName:"BASE64",baseSize:64}:/^[A-Za-z0-9]+$/.test(t)?{setName:"ALPHANUMERIC",baseSize:62}:/^[\x20-\x7E]+$/.test(t)?{setName:"ASCII_PRINTABLE",baseSize:95}:{setName:"SPECIAL",baseSize:128}}function Te(t){if(!t||t.length===0)return 0;let e=ve(t),{baseSize:i}=be(t),n=Math.log2(i);if(n<=0)return 0;let s=Math.min(1,e/n);return Math.round(s*100)/100}var yt=[/\bplaceholder\b/i,/\byour[_-]?(?:api)?[_-]?key\b/i,/\byour[_-]?secret\b/i,/\byour[_-]?token\b/i,/\binsert[_-]?here\b/i,/\breplace[_-]?me\b/i,/\benter[_-]?your\b/i,/\bchange[_-]?me\b/i,/\bdummy\b/i,/\bfake[_-]?token\b/i,/xxxx+/i,/\btest[_-]?value\b/i,/AKIAIOSFODNN7EXAMPLE/i,/wJalrXUtnFEMI\/K7MDENG\/bPxRfiCYEXAMPLEKEY/i,/^123456789[0-9]*$/,/^abcdef[a-z0-9]*$/i,/00000000[0-9]*/,/sk_live_example/i,/ghp_example/i,/:\/\/[^:]+:(?:password|secret|changeme|pass|admin|test|postgres|root)@(?:localhost|127\.0\.0\.1)(?::\d+)?\b/i,/:\/\/(?:postgres|root):(postgres|root)@(?:localhost|127\.0\.0\.1)(?::\d+)?\b/i],kt=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,St=/^(?:mock|dummy|placeholder|fake|sample)_(?:key|token|secret|password|pwd|cred)$/i;function _e(t,e,i){if(/(?:process\.env|import\.meta\.env|os\.environ|ENV[\[\.])/.test(t))return{isFalsePositive:!0,reason:"Environment variable lookup expression, not a hard-coded credential literal",confidencePenalty:100};if(/^(?:passwordRequired|required_field|required|optional|placeholder|changeme|default|test|dummy|example|string|undefined|null)$/i.test(t))return{isFalsePositive:!0,reason:"Common non-secret schema or form attribute value",confidencePenalty:100};for(let s of yt)if(s.test(t))return{isFalsePositive:!0,reason:`Matched known documentation/placeholder pattern: ${s.source}`,confidencePenalty:100};if(e&&St.test(e)&&!t.startsWith("AKIA")&&!t.startsWith("ghp_"))return{isFalsePositive:!0,reason:`Variable identifier indicates placeholder: ${e}`,confidencePenalty:100};let n=new Set(t.split("")).size;if(t.length>=10&&n<=3)return{isFalsePositive:!0,reason:"Low character diversity (repetitive filler characters)",confidencePenalty:95};if(kt.test(t)&&!e?.match(/secret|token|api_?key/i))return{isFalsePositive:!0,reason:"Standard UUID identifier without credential context",confidencePenalty:90};if(i){let s=/(?:docs|documentation|tutorials|guides)\/|readme\.md/i.test(i);if(/(?:example|sample|\.example|\.sample)/i.test(i)&&/example|your_/i.test(t))return{isFalsePositive:!0,reason:"Sample configuration value inside template/example file",confidencePenalty:90};if(s&&!t.startsWith("ghp_")&&!t.startsWith("AKIA"))return{isFalsePositive:!1,confidencePenalty:25}}return{isFalsePositive:!1,confidencePenalty:0}}function Pe(t){if(!/^(AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}$/.test(t))return{isValid:!1,confidenceBonus:0,reason:"Invalid AWS key length or character set"};let e=t.substring(0,4);return{isValid:!0,confidenceBonus:10,reason:{AKIA:"Standard permanent IAM user access key",ASIA:"Temporary STS session access key",ABIA:"AWS Backup access key",ACCA:"AWS CodeCommit access key"}[e]||"Valid AWS Access Key ID structure"}}function Fe(t){let e=/^sk_live_[0-9a-zA-Z]{24,100}$/.test(t)||/^rk_live_[0-9a-zA-Z]{24,100}$/.test(t),i=/^sk_test_[0-9a-zA-Z]{24,100}$/.test(t)||/^rk_test_[0-9a-zA-Z]{24,100}$/.test(t);return!e&&!i?{isValid:!1,confidenceBonus:0,reason:"Does not match official Stripe secret key format"}:{isValid:!0,confidenceBonus:e?12:5,reason:e?"Production live Stripe Secret Key":"Stripe Test API key"}}function $e(t){return/^ghp_[A-Za-z0-9_]{36}$/.test(t)?{isValid:!0,confidenceBonus:12,reason:"GitHub Personal Access Token (Classic)"}:/^gho_[A-Za-z0-9_]{36}$/.test(t)?{isValid:!0,confidenceBonus:10,reason:"GitHub OAuth Access Token"}:/^ghs_[A-Za-z0-9_]{36}$/.test(t)?{isValid:!0,confidenceBonus:10,reason:"GitHub Server-to-server token"}:/^github_pat_[A-Za-z0-9_]{82}$/.test(t)?{isValid:!0,confidenceBonus:15,reason:"GitHub Fine-Grained Personal Access Token"}:{isValid:!1,confidenceBonus:0,reason:"Invalid GitHub token prefix or length"}}function Le(t){let e=t.split(".");if(e.length!==3)return{isValid:!1,confidenceBonus:0,reason:"Not a 3-part dot-separated JWT"};try{let i=Buffer.from(e[0],"base64url").toString("utf8"),n=JSON.parse(i);if(n&&typeof n=="object"&&n.alg)return{isValid:!0,confidenceBonus:15,reason:`Valid JWT structure with signature algorithm: ${n.alg}`}}catch{}return{isValid:!1,confidenceBonus:0,reason:"Malformed JWT header JSON payload"}}function De(t){try{let e=new URL(t);if(!["postgres:","postgresql:","mysql:","mongodb:","mongodb+srv:","redis:"].includes(e.protocol))return{isValid:!1,confidenceBonus:0,reason:"Unsupported database protocol scheme"};if(e.password&&e.password.length>0)return{isValid:!0,confidenceBonus:12,reason:`Database connection string containing credentials for user '${e.username||"default"}'`}}catch{let e=/^(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis):\/\/[^:\s'"]+:([^\s'"]+)@([a-zA-Z0-9_.-]+(?::[0-9]+)?\/[^\s'"`;]*)/i,i=t.match(e);if(i&&i[1])return{isValid:!0,confidenceBonus:10,reason:"Database connection URI structure matched with embedded password"}}return{isValid:!1,confidenceBonus:0,reason:"Invalid database connection URL structure"}}function Ne(t){return/^sk-proj-[A-Za-z0-9_-]{48,}$/.test(t)?{isValid:!0,confidenceBonus:15,reason:"Valid OpenAI Project API Key format"}:/^sk-admin-[A-Za-z0-9_-]{48,}$/.test(t)?{isValid:!0,confidenceBonus:15,reason:"Valid OpenAI Admin/Organization API Key format"}:/^sk-svcacct-[A-Za-z0-9_-]{48,}$/.test(t)?{isValid:!0,confidenceBonus:15,reason:"Valid OpenAI Service Account Key format"}:/^sk-[A-Za-z0-9]{32,48}$/.test(t)?{isValid:!0,confidenceBonus:10,reason:"Valid OpenAI Standard/Legacy API Key format"}:{isValid:!1,confidenceBonus:0,reason:"Invalid OpenAI API key structure"}}function Oe(t){return/^sk-ant-[A-Za-z0-9_-]{40,}$/.test(t)?{isValid:!0,confidenceBonus:15,reason:"Valid Anthropic Claude API Key format"}:{isValid:!1,confidenceBonus:0,reason:"Invalid Anthropic API key format"}}function Me(t){return/^AIza[0-9A-Za-z_-]{35}$/.test(t)?{isValid:!0,confidenceBonus:12,reason:"Valid Google Cloud / Gemini AIza service key signature"}:{isValid:!1,confidenceBonus:0,reason:"Invalid Google Cloud API key format"}}function Be(t){return/^xox[baprs]-[0-9A-Za-z-]{10,72}$/.test(t)?{isValid:!0,confidenceBonus:12,reason:`Valid Slack ${t.startsWith("xoxb")?"Bot Token":t.startsWith("xoxp")?"User Token":"OAuth Token"} signature`}:{isValid:!1,confidenceBonus:0,reason:"Invalid Slack token structure"}}function He(t){return/^hf_[A-Za-z0-9]{34}$/.test(t)?{isValid:!0,confidenceBonus:12,reason:"Valid Hugging Face User Access Token format"}:{isValid:!1,confidenceBonus:0,reason:"Invalid Hugging Face token structure"}}function ye(t,e,i,n,s,o){let r=[],c=t.baseConfidence;r.push({signal:"KNOWN_PATTERN_MATCH",description:`Matched recognized credential signature for ${t.provider} (${t.name})`,confidenceImpact:0,details:{ruleId:t.id,provider:t.provider}});let d=ve(e),l=Te(e),{setName:m}=be(e);if(t.minEntropy&&d<t.minEntropy?(c=Math.max(10,c-30),r.push({signal:"LOW_ENTROPY",description:`Low entropy score: ${d} bits/char below minimum threshold of ${t.minEntropy}`,confidenceImpact:-30,details:{shannonEntropy:d,minEntropy:t.minEntropy}})):d>=4.5?(c=Math.min(100,c+5),r.push({signal:"HIGH_ENTROPY",description:`Cryptographic entropy: ${d} bits/char (${m} set), indicates non-human randomness`,confidenceImpact:5,details:{shannonEntropy:d,normalizedEntropy:l,characterSet:m}})):d>=3.4?r.push({signal:"MODERATE_ENTROPY",description:`Moderate entropy: ${d} bits/char (${m} set)`,confidenceImpact:0,details:{shannonEntropy:d,normalizedEntropy:l,characterSet:m}}):(c=Math.max(10,c-15),r.push({signal:"LOW_ENTROPY",description:`Low entropy score: ${d} bits/char (${m} set)`,confidenceImpact:-15,details:{shannonEntropy:d,normalizedEntropy:l,characterSet:m}})),n.isSensitiveIdentifier||o?.isSensitiveProperty){let p=o?.variablePath||n.inferredVariable||"credential";c=Math.min(100,c+10),r.push({signal:"SENSITIVE_IDENTIFIER",description:`Assigned to sensitive identifier / property: '${p}'`,confidenceImpact:10,details:{identifier:p}})}else n.isBenignIdentifier&&(c=Math.max(10,c-25),r.push({signal:"BENIGN_IDENTIFIER",description:`Identifier name indicates mock or sample value: '${n.inferredVariable}'`,confidenceImpact:-25,details:{identifier:n.inferredVariable}}));o?.isEnvFallback&&(c=Math.min(100,c+12),r.push({signal:"ENV_FALLBACK_ASSIGNMENT",description:'Hardcoded literal provided as environment variable fallback (e.g. process.env.KEY || "...")',confidenceImpact:12})),o?.isAuthorizationHeader&&(c=Math.min(100,c+10),r.push({signal:"AUTHORIZATION_HEADER",description:"Passed in HTTP Authorization or Bearer token header context",confidenceImpact:10})),(i.isConfig||i.isSensitiveName)&&(c=Math.min(100,c+8),r.push({signal:"PRODUCTION_CONFIG_FILE",description:`Located in configuration or secret storage file (${i.fileExtension})`,confidenceImpact:8,details:{isConfig:i.isConfig,extension:i.fileExtension}})),i.isTest&&(c=Math.max(20,c-20),r.push({signal:"TEST_FILE_PENALTY",description:"Found inside test/mock directory structure",confidenceImpact:-20})),i.isDoc&&(c=Math.max(20,c-25),r.push({signal:"DOCUMENTATION_PENALTY",description:"Found inside documentation or markdown guide",confidenceImpact:-25}));let a;t.id==="aws-access-key"?a=Pe(e):t.id==="stripe-secret-key"?a=Fe(e):t.id==="github-pat"?a=$e(e):t.id==="jwt-token"?a=Le(e):t.id==="database-url"?a=De(e):t.id==="openai-api-key"?a=Ne(e):t.id==="anthropic-api-key"?a=Oe(e):t.id==="google-api-key"?a=Me(e):t.id==="slack-bot-token"?a=Be(e):t.id==="huggingface-token"&&(a=He(e)),a&&a.isValid&&(c=Math.min(100,c+a.confidenceBonus),r.push({signal:"STRUCTURAL_VALIDATION_PASSED",description:`Structural validation verified: ${a.reason}`,confidenceImpact:a.confidenceBonus}));let u=_e(e,n.inferredVariable,s);if(u.isFalsePositive)return{confidence:0,evidence:{items:[{signal:"KNOWN_PLACEHOLDER_REJECTED",description:u.reason||"Placeholder value rejected",confidenceImpact:-100}],shannonEntropy:d,normalizedEntropy:l,characterSet:m,surroundingCode:{before:n.surroundingBefore,targetLine:n.matchedLine,after:n.surroundingAfter,inferredVariable:n.inferredVariable},fileContext:{fileExtension:i.fileExtension,isConfig:i.isConfig,isTest:i.isTest,isDoc:i.isDoc,isSensitiveName:i.isSensitiveName,isExampleOrSample:i.isExampleOrSample}},isSuppressed:!0,suppressReason:u.reason};u.confidencePenalty>0&&(c=Math.max(10,c-u.confidencePenalty));let g=Math.max(0,Math.min(100,Math.round(c))),h={items:r,shannonEntropy:d,normalizedEntropy:l,characterSet:m,surroundingCode:{before:n.surroundingBefore,targetLine:n.matchedLine,after:n.surroundingAfter,inferredVariable:n.inferredVariable},fileContext:{fileExtension:i.fileExtension,isConfig:i.isConfig,isTest:i.isTest,isDoc:i.isDoc,isSensitiveName:i.isSensitiveName,isExampleOrSample:i.isExampleOrSample}};return{confidence:g,evidence:h,isSuppressed:!1}}function ke(t,e,i,n){let s=[],o=0,r=Math.min(40,Math.round(t.baseRiskWeight/100*40));o+=r,s.push({factor:"CREDENTIAL_SEVERITY",weight:40,scoreContribution:r,explanation:`${t.provider} ${t.name} has high inherent privilege capability`});let c=Math.round(e/100*25);o+=c,s.push({factor:"CONFIDENCE_LEVEL",weight:25,scoreContribution:c,explanation:`Multi-signal verification confidence is ${e}%`});let d=5,l="Standard source code file";i.isConfig||i.isSensitiveName?(d=15,l="Located in sensitive deployment / environment configuration"):i.isTest?(d=0,l="Located in test / fixture codebase with reduced operational blast radius"):i.isDoc&&(d=0,l="Located in documentation context"),o+=d,s.push({factor:"STORAGE_ENVIRONMENT",weight:15,scoreContribution:d,explanation:l});let m=5,a="Found in local uncommitted working tree";n&&(n.isRemote?(m=20,a="Pushed to remote repository branch (external exposure risk)"):n.isPresentInHistory?(m=16,a=`Committed to Git history across ${n.branches.length||1} branch(es) (${n.exposureDurationDays} days exposure)`):n.isPresentInHead&&(m=12,a="Committed in current HEAD commit")),o+=m,s.push({factor:"EXPOSURE_REACH",weight:20,scoreContribution:m,explanation:a});let u=Math.max(0,Math.min(100,Math.round(o))),g="LOW";u>=76?g="CRITICAL":u>=51?g="HIGH":u>=26?g="MEDIUM":g="LOW";let h=At(u,n),p=`${g} Risk (${u}/100) \u2014 ${t.name}. ${h.summary}`;return{score:u,tier:g,factors:s,blastRadius:h,summary:p}}function At(t,e){let i=[],n=Math.round(t*.5),s=e?e.isPresentInHead:!0,o=e?e.isPresentInHistory:!1,r=e?.isPresentInHistory?1:0,c=e?.branches||["main"],d=c.length,l=e?.isRemote||!1,m=e?.exposureDurationDays||0;s&&(i.push("Active working tree contains exposed secret"),n+=15),o&&(i.push(`Git history contains commit records across ${d} branch(es)`),n+=20),l&&(i.push("Secret has been synchronized to remote tracking branches"),n+=25),m>7&&(i.push(`Exposure duration exceeds ${m} days without rotation`),n+=10),n=Math.max(0,Math.min(100,n));let a="CONTAINED";n>=75?a="SEVERE":n>=50?a="EXTENSIVE":n>=25?a="MODERATE":a="CONTAINED";let u=`Blast Radius: ${a} (${n}/100) \u2014 ${l?"Remote & history exposure":o?"Historical commit exposure":"Contained to local working tree"}`;return{level:a,score:n,workingTreeExposed:s,gitHistoryExposed:o,commitCount:r,branchCount:d,branches:c,remoteExposed:l,exposureDurationDays:m,summary:u,factors:i}}var B=I(require("fs")),Ge=I(require("path"));var Ke=I(require("crypto"));function Q(t){if(!t)return"";let e=t.length;if(e<=8)return"\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022";let i=Math.min(4,Math.floor(e/4)),n=Math.min(3,Math.floor(e/4)),s=Math.max(4,e-i-n),o=t.substring(0,i),r=t.substring(e-n),c="\u2022".repeat(Math.min(12,s));return`${o}${c}${r}`}function Se(t){return Ke.createHash("sha256").update(t).digest("hex").substring(0,16)}function re(t){return t.replace(/\\/g,"\\\\").replace(/"/g,'\\"').replace(/\$/g,"\\$").replace(/\n/g,"\\n").replace(/\r/g,"\\r")}function Ae(t,e,i,n,s){let o=t.suggestedEnvName(s),r=`process.env.${o}`,c=Q(e),d=re(e),l=[`1. Revoke / rotate credential immediately with provider: ${t.provider}`,`2. Migrate secret value to local .env file (${o})`,`3. Replace hardcoded literal in ${i} with ${r}`,"4. Verify .env is listed in .gitignore so it is never committed","5. If committed previously, purge from Git history using git-filter-repo or BFG","6. Rescan file and commit to verify exposure is eliminated"],m=`${o}="${d}"`,a=`${o}=your_${o.toLowerCase()}_here`,u=`# WARNING: Use BFG Repo Cleaner to purge secrets from history (safer than filter-repo --invert-paths):
#   java -jar bfg.jar --replace-text secrets.txt <repo-dir>
# Where secrets.txt lists the exact literal to redact (one per line).
# Then force-push: git push --force --all && git push --force --tags
# Alternatively with git-filter-repo (rewrites content, not paths):
#   git filter-repo --replace-text secrets.txt`,g=`--- a/${i}
+++ b/${i}
@@ -${n},1 +${n},1 @@
- ... "${c}" ...
+ ... ${r} ...`;return{steps:l,envVarName:o,replacementCode:r,envFileSnippet:m,envExampleSnippet:a,gitHistoryPurgeCommand:u,diffPreview:g}}function Ve(t,e,i){let n=t.split(/\r?\n/),s=new Map;for(let o of n){let r=o.trim();if(!r||r.startsWith("#"))continue;let c=r.indexOf("=");if(c!==-1){let d=r.substring(0,c).trim(),l=r.substring(c+1).trim();(l.startsWith('"')&&l.endsWith('"')||l.startsWith("'")&&l.endsWith("'"))&&(l=l.substring(1,l.length-1)),s.set(d,l)}}if(s.has(e)){let o=s.get(e);if(o===re(i)||o===i)return{varName:e,isReused:!0};let r=2;for(;s.has(`${e}_${r}`);){if(s.get(`${e}_${r}`)===i)return{varName:`${e}_${r}`,isReused:!0};r++}return{varName:`${e}_${r}`,isReused:!1}}return{varName:e,isReused:!1}}function We(t){let e=Ge.join(t,".gitignore");if(B.existsSync(e)){let i=B.readFileSync(e,"utf8");if(!i.split(/\r?\n/).some(o=>/^\s*\.env(?:\s|$)/.test(o))){let o=i.endsWith(`
`)||i.length===0?"":`
`;B.appendFileSync(e,`${o}# Credentials
.env
.env.*.local
`,"utf8")}}else B.writeFileSync(e,`# Credentials
.env
.env.*.local
`,"utf8");try{let{execFileSync:i}=require("child_process");try{throw i("git",["ls-files","--error-unmatch",".env"],{cwd:t,stdio:"ignore"}),new Error('.env is already tracked in Git index. Run "git rm --cached .env" to untrack it before storing secrets.')}catch(n){if(n.message&&n.message.includes("already tracked in Git index"))throw n}try{i("git",["check-ignore","-q",".env"],{cwd:t,stdio:"ignore"})}catch{throw new Error(".env is not ignored by Git according to git check-ignore.")}}catch(i){if(i.message&&(i.message.includes("already tracked")||i.message.includes("not ignored by Git")))throw i}}function ze(t){return Ue.createHash("sha256").update(t.replace(/\\/g,"/")).digest("hex").slice(0,8)}function ee(t,e,i={}){let n=typeof i=="string"?{workspaceRoot:i}:i,s=n.rules||Ie,o=n.workspaceRoot,r=we(e,o),c=[],d=null;function l(){if(!d){d=[0];for(let p=0;p<t.length;p++)t.charCodeAt(p)===10&&d.push(p+1)}return d}function m(p){let v=l(),b=0,S=v.length-1;for(;b<=S;){let C=b+S>>1;if(v[C]<=p){if(C===v.length-1||v[C+1]>p)return{line:C+1,column:p-v[C]+1};b=C+1}else S=C-1}return{line:1,column:p+1}}let a=null;function u(p){if(t.length<=1024*1024)return a||(a=t.split(/\r?\n/)),{lines:a,relativeTargetIdx:p-1};let v=l(),b=p-1,S=Math.max(0,b-30),C=Math.min(v.length-1,b+30),y=v[S],R=C+1<v.length?v[C+1]:t.length;return{lines:t.substring(y,R).split(/\r?\n/),relativeTargetIdx:b-S}}for(let p of s){p.pattern.lastIndex=0;let v;for(;(v=p.pattern.exec(t))!==null;){let b=v[1]!==void 0?v[1]:v[0],S=v[1]!==void 0?v[0].indexOf(v[1]):0,C=v.index+(S>=0?S:0),{line:y,column:R}=m(C),x=u(y),F=fe(x.lines,x.relativeTargetIdx),j=he(x.lines,x.relativeTargetIdx,e),_=ye(p,b,r,F,e,j);if(_.isSuppressed)continue;let Z=n.minEntropyThreshold??p.minEntropy;if(Z&&_.evidence.shannonEntropy<Z)continue;let M=e;if(o){let X=V.relative(o,e);!X.startsWith("..")&&!V.isAbsolute(X)&&(M=X)}let Y=ke(p,_.confidence,r),q=Ae(p,b,M,y,F.inferredVariable),ue=ze(M),J=Se(b),me=`sec_${J}_${ue}_${y}`,ge=Q(b),H={id:me,fingerprint:J,type:p.name,provider:p.provider,file:M,fullPath:e,line:y,column:R,length:b.length,rawSecret:b,redactedSecret:ge,confidence:_.confidence,risk:Y.tier,riskAssessment:Y,evidence:_.evidence,remediation:q,status:"ACTIVE",detectedAt:new Date().toISOString(),signals:_.evidence.items.map(X=>X.description),exampleFix:q.replacementCode,entropy:_.evidence.shannonEntropy};c.push(H)}}let g=/["']([^"'\r\n]{2,80})["']\s*\+\s*["']([^"'\r\n]{8,120})["']/g,h;for(;(h=g.exec(t))!==null;){let p=h[1]+h[2],v=h.index;for(let b of s){b.pattern.lastIndex=0;let S;for(;(S=b.pattern.exec(p))!==null;){let C=S[1]||S[0],{line:y,column:R}=m(v),x=u(y),F=fe(x.lines,x.relativeTargetIdx),j=he(x.lines,x.relativeTargetIdx,e),_=ye(b,C,r,F,e,j);if(_.isSuppressed)continue;let Z=n.minEntropyThreshold??b.minEntropy;if(Z&&_.evidence.shannonEntropy<Z)continue;let M=e;if(o){let H=V.relative(o,e);!H.startsWith("..")&&!V.isAbsolute(H)&&(M=H)}let Y=ke(b,_.confidence,r),q=Ae(b,C,M,y,F.inferredVariable);_.evidence.items.unshift({signal:"ADVERSARIAL_DEOBFUSCATION_RESOLVED",description:"Resolved split string concatenation",confidenceImpact:10});let ue=ze(M),J=Se(C),me=`sec_${J}_${ue}_${y}`,ge=Q(C);c.push({id:me,fingerprint:J,type:b.name,provider:b.provider,file:M,fullPath:e,line:y,column:R,length:h[0].length,rawSecret:C,redactedSecret:ge,confidence:Math.min(100,_.confidence+5),risk:Y.tier,riskAssessment:Y,evidence:_.evidence,remediation:q,status:"ACTIVE",detectedAt:new Date().toISOString(),signals:_.evidence.items.map(H=>H.description),exampleFix:q.replacementCode,entropy:_.evidence.shannonEntropy})}}}return Et(c)}function Et(t){let e=[];for(let i of t){let n=e.findIndex(s=>s.file===i.file&&s.line===i.line&&(s.rawSecret.includes(i.rawSecret)||i.rawSecret.includes(s.rawSecret)));if(n===-1)e.push(i);else{let s=e[n];(s.provider==="Generic Credential"&&i.provider!=="Generic Credential"||i.confidence>s.confidence)&&(e[n]=i)}}return e}var ae=class{diagnosticCollection;currentFindings=new Map;ignoredFindings=new Set;onFindingsChangedEmitter=new w.EventEmitter;onFindingsChanged=this.onFindingsChangedEmitter.event;minEntropy;constructor(){this.diagnosticCollection=w.languages.createDiagnosticCollection("secret-leak-detector")}setMinEntropy(e){this.minEntropy=e}getDiagnosticCollection(){return this.diagnosticCollection}getAllFindings(){let e=[];for(let i of this.currentFindings.values())e.push(...i);return e}clear(){this.diagnosticCollection.clear(),this.currentFindings.clear(),this.onFindingsChangedEmitter.fire([])}ignoreFinding(e){this.ignoredFindings.add(e);for(let[i,n]of this.currentFindings.entries()){let s=n.filter(o=>o.id!==e);if(s.length!==n.length){this.currentFindings.set(i,s);let o=w.Uri.file(i),r=this.diagnosticCollection.get(o);if(r){let c=r.filter(d=>(typeof d.code=="object"?d.code?.value:d.code)!==e);this.diagnosticCollection.set(o,c)}}}this.onFindingsChangedEmitter.fire(this.getAllFindings())}setIgnoredFindings(e){this.ignoredFindings=new Set(e)}getIgnoredFindings(){return Array.from(this.ignoredFindings)}scanDocument(e){if(e.uri.scheme!=="file")return[];let i=e.getText(),n=w.workspace.getWorkspaceFolder(e.uri),o={workspaceRoot:n?n.uri.fsPath:void 0,minEntropyThreshold:this.minEntropy},c=ee(i,e.uri.fsPath,o).filter(l=>!this.ignoredFindings.has(l.id));this.currentFindings.set(e.uri.fsPath,c);let d=[];for(let l of c){let m=Math.max(0,l.line-1),a=Math.max(0,l.column-1),u=new w.Position(m,a),g=e.offsetAt(u),h=e.positionAt(g+l.length),p=new w.Range(u,h),v=w.DiagnosticSeverity.Warning;l.risk==="CRITICAL"||l.risk==="HIGH"?v=w.DiagnosticSeverity.Error:l.risk==="LOW"&&(v=w.DiagnosticSeverity.Information);let b=typeof l.remediation=="string"?l.remediation:l.remediation?.steps?.[0]||"Migrate to .env",S=new w.Diagnostic(p,`[Secret Leak Detector] ${l.type} detected! Confidence: ${l.confidence}%. ${b}`,v);S.code={value:l.id,target:w.Uri.parse("https://github.com/MokuLakshithReddy/Secret_Leak_Detector")},S.source="Secret Leak Detector",d.push(S)}return this.diagnosticCollection.set(e.uri,d),this.onFindingsChangedEmitter.fire(this.getAllFindings()),c}removeDocument(e){this.diagnosticCollection.delete(e),this.currentFindings.delete(e.fsPath),this.onFindingsChangedEmitter.fire(this.getAllFindings())}dispose(){this.diagnosticCollection.dispose(),this.onFindingsChangedEmitter.dispose()}};var E=I(require("vscode")),$=I(require("fs")),te=I(require("path"));function Ct(t,e){switch(te.extname(t).toLowerCase()){case".py":return`os.environ.get("${e}")`;case".go":return`os.Getenv("${e}")`;case".rb":return`ENV['${e}']`;case".php":return`getenv('${e}')`;case".java":case".kt":return`System.getenv("${e}")`;case".rs":return`std::env::var("${e}").unwrap()`;case".sh":case".bash":case".zsh":return`"\${${e}}"`;case".yaml":case".yml":case".toml":case".env":return`\${${e}}`;case".js":case".jsx":case".ts":case".tsx":case".mjs":case".cjs":default:return`process.env.${e}`}}var W=class{static providedCodeActionKinds=[E.CodeActionKind.QuickFix];diagnosticProvider;constructor(e){this.diagnosticProvider=e}provideCodeActions(e,i,n){let s=[],o=n.diagnostics.filter(c=>c.source==="Secret Leak Detector");if(o.length===0)return s;let r=this.diagnosticProvider.getAllFindings();for(let c of o){let d=typeof c.code=="object"?c.code?.value:c.code,l=r.find(g=>g.id===d);if(!l||e.getText(c.range)!==l.rawSecret)continue;let a=this.createMoveToEnvAction(e,c.range,l);s.push(a);let u=new E.CodeAction("Ignore this finding (False Positive)",E.CodeActionKind.QuickFix);u.command={command:"secret-leak-detector.ignoreFinding",title:"Ignore Finding",arguments:[l.id]},s.push(u)}return s}createMoveToEnvAction(e,i,n){let s=new E.CodeAction(`\u{1F6E1}\uFE0F Move ${n.type} to .env and replace with environment variable`,E.CodeActionKind.QuickFix);return s.isPreferred=!0,s.command={command:"secret-leak-detector.remediateFinding",title:"Move to .env",arguments:[e.uri,i,n]},s}static async executeRemediation(e,i,n){let s=E.workspace.getWorkspaceFolder(e);if(!s){E.window.showErrorMessage("No workspace folder found to save .env file.");return}let o=await E.workspace.openTextDocument(e);if(o.getText(i)!==n.rawSecret){E.window.showErrorMessage("The secret at the target location has changed or was already removed.");return}let r=s.uri.fsPath,c=te.join(r,".env"),d=n.remediation?.envVarName;d||(n.type.includes("AWS Access Key")?d="AWS_ACCESS_KEY_ID":n.type.includes("AWS Secret")?d="AWS_SECRET_ACCESS_KEY":n.type.includes("GitHub")?d="GITHUB_TOKEN":n.type.includes("OpenAI")?d="OPENAI_API_KEY":n.type.includes("Anthropic")?d="ANTHROPIC_API_KEY":n.type.includes("Stripe")?d="STRIPE_SECRET_KEY":n.type.includes("Slack")?d="SLACK_TOKEN":n.type.includes("Database")?d="DATABASE_URL":d=`${n.provider.replace(/[^a-zA-Z0-9]/g,"_").toUpperCase()}_API_KEY`);let l="",m=!1;if($.existsSync(c)){m=!0;try{l=$.readFileSync(c,"utf8")}catch(y){E.window.showErrorMessage(`Failed to read .env file: ${y}`);return}}let{varName:a,isReused:u}=Ve(l,d,n.rawSecret);try{We(r)}catch(y){E.window.showErrorMessage(`Failed to verify .gitignore security: ${y.message||y}`);return}let g=i,h=!1;if(i.start.character>0){let y=i.start.translate(0,-1),R=i.end.translate(0,1),x=o.getText(new E.Range(y,i.start)),F=o.getText(new E.Range(i.end,R));(x==='"'&&F==='"'||x==="'"&&F==="'")&&(g=new E.Range(y,R),h=!0)}let p=Ct(e.fsPath,a),v=new E.WorkspaceEdit;if(v.replace(e,g,p),!await E.workspace.applyEdit(v)){E.window.showErrorMessage("Failed to modify source document. Remediation aborted with zero file alterations.");return}let S=re(n.rawSecret),C=`${a}="${S}"
`;try{if(!u)if(!m)$.writeFileSync(c,C,{mode:384,encoding:"utf8"});else{let x=l.endsWith(`
`)||l.length===0?"":`
`;$.appendFileSync(c,`${x}${C}`,{mode:384,encoding:"utf8"})}let y=te.join(r,".env.example"),R=`${a}=your_${a.toLowerCase()}_here
`;if(!$.existsSync(y)||!$.readFileSync(y,"utf8").includes(a)){let x=$.existsSync(y)?$.readFileSync(y,"utf8"):"",F=x.endsWith(`
`)||x.length===0?"":`
`;$.appendFileSync(y,`${F}${R}`,"utf8")}}catch(y){let R=new E.Range(g.start,g.start.translate(0,p.length)),x=new E.WorkspaceEdit;x.replace(e,R,h?`"${n.rawSecret}"`:n.rawSecret),await E.workspace.applyEdit(x),E.window.showErrorMessage(`Failed to write to .env: ${y}. Document edit was safely rolled back.`);return}E.window.showInformationMessage(`\u2705 Moved ${n.type} to .env (${a}) and verified .gitignore protection!`)}};var k=I(require("vscode")),ce=class{_onDidChangeTreeData=new k.EventEmitter;onDidChangeTreeData=this._onDidChangeTreeData.event;findings=[];updateFindings(e){this.findings=e,this._onDidChangeTreeData.fire()}getTreeItem(e){return e}getChildren(e){if(!e){if(this.findings.length===0){let s=new N("No Leaks Detected (Safe)",k.TreeItemCollapsibleState.None);return s.iconPath=new k.ThemeIcon("shield-check",new k.ThemeColor("testing.iconPassed")),s.description="Workspace is clean",Promise.resolve([s])}let i=["CRITICAL","HIGH","MEDIUM","LOW"],n=[];for(let s of i){let o=this.findings.filter(r=>r.risk===s).length;if(o>0){let r=new N(`${s} Risk (${o})`,k.TreeItemCollapsibleState.Expanded,s);s==="CRITICAL"?r.iconPath=new k.ThemeIcon("error",new k.ThemeColor("errorForeground")):s==="HIGH"?r.iconPath=new k.ThemeIcon("warning",new k.ThemeColor("editorWarning.foreground")):s==="MEDIUM"?r.iconPath=new k.ThemeIcon("info",new k.ThemeColor("editorInfo.foreground")):r.iconPath=new k.ThemeIcon("pass",new k.ThemeColor("testing.iconPassed")),n.push(r)}}return Promise.resolve(n)}if(e.contextValue){let i=e.contextValue,s=this.findings.filter(o=>o.risk===i).map(o=>{let r=new N(`${o.type}`,k.TreeItemCollapsibleState.None);return r.description=`${o.file}:${o.line}`,r.tooltip=new k.MarkdownString(`**${o.type}** (${o.provider})

- **Risk:** ${o.risk}
- **Confidence:** ${o.confidence}%
- **Entropy:** ${o.entropy} bits/char
- **Secret:** \`${o.redactedSecret}\`

*${o.remediation}*`),r.iconPath=new k.ThemeIcon("key"),r.command={command:"vscode.open",title:"Jump to Secret",arguments:[k.Uri.file(o.fullPath),{selection:new k.Range(o.line-1,o.column-1,o.line-1,o.column-1+o.length)}]},r});return Promise.resolve(s)}return Promise.resolve([])}},de=class{_onDidChangeTreeData=new k.EventEmitter;onDidChangeTreeData=this._onDidChangeTreeData.event;findingsCount=0;isGit=!0;update(e,i){this.findingsCount=e,this.isGit=i,this._onDidChangeTreeData.fire()}getTreeItem(e){return e}getChildren(){let e=[],i=new N(this.findingsCount===0?"Status: Protected":`Status: ${this.findingsCount} Leaks Active`,k.TreeItemCollapsibleState.None);i.iconPath=new k.ThemeIcon(this.findingsCount===0?"check":"alert",this.findingsCount===0?new k.ThemeColor("testing.iconPassed"):new k.ThemeColor("errorForeground")),e.push(i);let n=new N("Run Full Workspace Scan",k.TreeItemCollapsibleState.None);n.iconPath=new k.ThemeIcon("search"),n.command={command:"secret-leak-detector.scanWorkspace",title:"Scan Workspace"},e.push(n);let s=new N("Check Git Staged Changes",k.TreeItemCollapsibleState.None);s.iconPath=new k.ThemeIcon("git-commit"),s.command={command:"secret-leak-detector.scanStaged",title:"Scan Staged Changes"},e.push(s);let o=new N("Open Interactive Dashboard",k.TreeItemCollapsibleState.None);o.iconPath=new k.ThemeIcon("dashboard"),o.command={command:"secret-leak-detector.openDashboard",title:"Open Dashboard"},e.push(o);let r=new N("Install Pre-Commit Hook",k.TreeItemCollapsibleState.None);return r.iconPath=new k.ThemeIcon("terminal"),r.command={command:"secret-leak-detector.installGitHook",title:"Install Hook"},e.push(r),Promise.resolve(e)}},N=class extends k.TreeItem{constructor(e,i,n){super(e,i),this.contextValue=n}};var T=I(require("vscode")),je=I(require("crypto"));function Ee(t){let e=typeof t.remediation=="string"?t.remediation:t.remediation?.steps?.join("; ")||"Rotate and move to .env",i=t.exampleFix||t.remediation?.replacementCode||"";return{id:t.id,type:t.type,provider:t.provider,file:t.file,fullPath:t.fullPath,line:t.line,column:t.column,redactedSecret:t.redactedSecret,confidence:t.confidence,entropy:t.entropy??0,risk:t.risk,remediationText:e,exampleFix:i}}var K=class t{static currentPanel;static viewType="secretLeakDetectorDashboard";_panel;_extensionUri;_disposables=[];_findings=[];static createOrShow(e,i){let n=T.window.activeTextEditor?T.window.activeTextEditor.viewColumn:void 0;if(t.currentPanel){t.currentPanel._panel.reveal(n),t.currentPanel.updateFindings(i);return}let s=T.window.createWebviewPanel(t.viewType,"\u{1F510} Secret Leak Detector Dashboard",n||T.ViewColumn.One,{enableScripts:!0,retainContextWhenHidden:!0,localResourceRoots:[e]});t.currentPanel=new t(s,e,i)}constructor(e,i,n){this._panel=e,this._extensionUri=i,this._findings=n,this._update(),this._panel.onDidDispose(()=>this.dispose(),null,this._disposables),this._panel.webview.onDidReceiveMessage(async s=>{switch(s.command){case"scanWorkspace":T.commands.executeCommand("secret-leak-detector.scanWorkspace");return;case"scanStaged":T.commands.executeCommand("secret-leak-detector.scanStaged");return;case"installHook":T.commands.executeCommand("secret-leak-detector.installGitHook");return;case"openFile":if(s.file&&s.line){let o=await T.workspace.openTextDocument(T.Uri.file(s.file));await T.window.showTextDocument(o,{selection:new T.Range(s.line-1,0,s.line-1,0)})}return}},null,this._disposables)}updateFindings(e){this._findings=e;let i=this._findings.map(Ee);this._panel.webview.postMessage({command:"updateData",findings:i})}dispose(){for(t.currentPanel=void 0,this._panel.dispose();this._disposables.length;){let e=this._disposables.pop();e&&e.dispose()}}_update(){this._panel.webview.html=this._getHtmlForWebview()}_getHtmlForWebview(){let e=je.randomBytes(16).toString("base64"),i=this._findings.map(Ee),n=JSON.stringify(i).replace(/</g,"\\u003c");return`<!DOCTYPE html>
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
</html>`}};var it=require("child_process"),st=require("util"),A=I(require("fs")),P=I(require("path"));var G=require("child_process"),Ze=require("util"),U=I(require("path"));var le=(0,Ze.promisify)(G.execFile),z=["-c","core.quotepath=false","--literal-pathspecs"];function Ye(t){return t.startsWith("R")||t.startsWith("C")}function qe(t){return t.startsWith("D")}function xt(t){try{let e=(0,G.execFileSync)("git",["rev-parse","--show-toplevel"],{cwd:t,encoding:"utf8"}).trim();if(e)return U.resolve(e)}catch{}return t}async function It(t){try{let{stdout:e}=await le("git",["rev-parse","--show-toplevel"],{cwd:t,encoding:"utf8"}),i=e.trim();if(i)return U.resolve(i)}catch{}return t}function Je(t){let e=xt(t),i;try{i=(0,G.execFileSync)("git",[...z,"diff","--cached","-z","--name-status"],{cwd:e,encoding:"utf8",maxBuffer:10*1024*1024})}catch(r){return{status:"ERROR",findings:[],error:`git diff --cached failed: ${r.message||String(r)}`}}let n=i.split("\0").filter(Boolean),s=[],o=0;for(let r=0;r<n.length;){let c=n[r],l=n[r+1],m=2;Ye(c)&&n[r+2]!==void 0&&(l=n[r+2],m=3),r+=m;let a=l.replace(/\\/g,"/");if(a==="/dev/null"||qe(c))continue;let u;try{u=(0,G.execFileSync)("git",[...z,"show",`:${a}`],{cwd:e,encoding:"utf8",maxBuffer:10*1024*1024})}catch(p){s.push({type:"SCAN_ERROR",provider:"Internal",file:a,fullPath:U.join(e,l),line:0,column:0,rawSecret:"",redactedSecret:"",confidence:0,risk:"CRITICAL",signals:[`git show failed: ${p.message||String(p)}`],evidence:{score:0,items:[]},riskAssessment:{score:100,blastRadius:{level:"UNKNOWN",summary:"Staged blob unreadable \u2014 scan blocked"},factors:[]},remediation:{steps:[],envVarName:"",replacementCode:"",envFileSnippet:"",envExampleSnippet:"",gitHistoryPurgeCommand:"",diffPreview:""}});continue}let g=new Set;try{let p=(0,G.execFileSync)("git",[...z,"diff","--cached","-U0","--",a],{cwd:e,encoding:"utf8",maxBuffer:10485760}),v=/^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/gm,b;for(;(b=v.exec(p))!==null;){let S=parseInt(b[1],10),C=b[2]!==void 0?parseInt(b[2],10):1;for(let y=0;y<C;y++)g.add(S+y)}}catch(p){return{status:"ERROR",findings:s,error:`Could not determine staged diff for '${a}': ${p.message||String(p)}`,filesScanned:o}}if(g.size===0)continue;let h=ee(u,a,{workspaceRoot:e});for(let p of h)g.has(p.line)&&s.push(p);o++}return s.length>0?{status:"FINDINGS",findings:s,filesScanned:o}:{status:"CLEAN",findings:[],filesScanned:o}}async function Xe(t){let e=await It(t),i;try{let{stdout:r}=await le("git",[...z,"diff","--cached","-z","--name-status"],{cwd:e,encoding:"utf8",maxBuffer:10485760});i=r}catch(r){return{status:"ERROR",findings:[],error:`git diff --cached failed: ${r.message||String(r)}`}}let n=i.split("\0").filter(Boolean),s=[],o=0;for(let r=0;r<n.length;){let c=n[r],l=n[r+1],m=2;Ye(c)&&n[r+2]!==void 0&&(l=n[r+2],m=3),r+=m;let a=l.replace(/\\/g,"/");if(a==="/dev/null"||qe(c))continue;let u;try{let{stdout:p}=await le("git",[...z,"show",`:${a}`],{cwd:e,encoding:"utf8",maxBuffer:10485760});u=p}catch(p){s.push({type:"SCAN_ERROR",provider:"Internal",file:a,fullPath:U.join(e,l),line:0,column:0,rawSecret:"",redactedSecret:"",confidence:0,risk:"CRITICAL",signals:[`git show failed: ${p.message||String(p)}`],evidence:{score:0,items:[]},riskAssessment:{score:100,blastRadius:{level:"UNKNOWN",summary:"Staged blob unreadable \u2014 scan blocked"},factors:[]},remediation:{steps:[],envVarName:"",replacementCode:"",envFileSnippet:"",envExampleSnippet:"",gitHistoryPurgeCommand:"",diffPreview:""}});continue}let g=new Set;try{let{stdout:p}=await le("git",[...z,"diff","--cached","-U0","--",a],{cwd:e,encoding:"utf8",maxBuffer:10485760}),v=/^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/gm,b;for(;(b=v.exec(p))!==null;){let S=parseInt(b[1],10),C=b[2]!==void 0?parseInt(b[2],10):1;for(let y=0;y<C;y++)g.add(S+y)}}catch(p){return{status:"ERROR",findings:s,error:`Could not determine staged diff for '${a}': ${p.message||String(p)}`,filesScanned:o}}if(g.size===0)continue;let h=ee(u,a,{workspaceRoot:e});for(let p of h)g.has(p.line)&&s.push(p);o++}return s.length>0?{status:"FINDINGS",findings:s,filesScanned:o}:{status:"CLEAN",findings:[],filesScanned:o}}var Qe=["LOW","MEDIUM","HIGH","CRITICAL"],Ce={LOW:1,MEDIUM:2,HIGH:3,CRITICAL:4},O="HIGH";function et(t,e=O){return(Ce[t]||0)>=(Ce[e]||Ce.CRITICAL)}var ne="# [SLD_HOOK_MANAGED]";function tt(t=O,e){let i=Qe.includes(t)?t:O,n=e?e.replace(/\\/g,"/"):"",s=n?n.replace(/'/g,"'\\''"):"",o=n?`# Scanner pinned to bundled CLI path
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
${ne}
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
`}var nt=(0,st.promisify)(it.execFile),pe=class{workspaceRoot;cliPath;constructor(e,i){if(this.workspaceRoot=e,i&&A.existsSync(i))this.cliPath=i;else if(process.env.SLD_CLI_PATH&&A.existsSync(process.env.SLD_CLI_PATH))this.cliPath=process.env.SLD_CLI_PATH;else{let n=[P.resolve(__dirname,"cli.js"),P.resolve(__dirname,"../cli/index.js"),P.resolve(__dirname,"../../dist/cli.js")];this.cliPath=n.find(s=>A.existsSync(s))}}async isGitRepo(){try{return await nt("git",["rev-parse","--is-inside-work-tree"],{cwd:this.workspaceRoot}),!0}catch{return!1}}async scanStagedChanges(){return Xe(this.workspaceRoot)}scanStagedChangesSync(){return Je(this.workspaceRoot)}formatTerminalBlockedMessage(e){let n=e.filter(d=>d.risk==="CRITICAL")[0]||e[0],s=typeof n.remediation=="string"?n.remediation:n.remediation?.steps?.join(`
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
`}async resolveHooksDir(){try{let{stdout:e}=await nt("git",["rev-parse","--git-path","hooks"],{cwd:this.workspaceRoot}),i=e.trim();return P.isAbsolute(i)?i:P.resolve(this.workspaceRoot,i)}catch{return P.join(this.workspaceRoot,".git","hooks")}}async installPreCommitHook(e){if(!await this.isGitRepo())return{success:!1,message:"Workspace is not a Git repository."};let i=await this.resolveHooksDir();if(!A.existsSync(i))try{A.mkdirSync(i,{recursive:!0})}catch(m){return{success:!1,message:`Could not create hooks directory (${i}): ${m}`}}let n=P.join(i,"pre-commit"),s=Date.now(),o=P.join(i,`pre-commit.sld-backup.${s}`),r=P.join(i,"pre-commit.sld-backup.latest"),c=ne;if(A.existsSync(n))try{let m=A.readFileSync(n,"utf8");m.includes(c)||(A.writeFileSync(o,m,{mode:493}),A.writeFileSync(r,o,"utf8"))}catch(m){return{success:!1,message:`Could not backup existing hook: ${m}`}}let d=e||this.cliPath;if(!d||!A.existsSync(d))return{success:!1,message:`Cannot install pre-commit hook: bundled CLI binary not found at '${d||"undefined"}'. Installation aborted.`};let l=tt(O,d);try{return A.writeFileSync(n,l,{mode:493}),{success:!0,message:`Pre-commit hook successfully installed to ${n}`}}catch(m){return{success:!1,message:`Failed to write hook file: ${m}`}}}async ensureHookIsPinned(e){if(!e||!A.existsSync(e)||!await this.isGitRepo())return!1;let i=await this.resolveHooksDir(),n=P.join(i,"pre-commit");if(!A.existsSync(n))return!1;try{let s=A.readFileSync(n,"utf8");if(!s.includes(ne))return!1;let o=e.replace(/\\/g,"/");if(!s.includes(o))return(await this.installPreCommitHook(e)).success}catch{return!1}return!0}async uninstallPreCommitHook(){let e=await this.resolveHooksDir(),i=P.join(e,"pre-commit"),n=P.join(e,"pre-commit.sld-backup.latest");if(!A.existsSync(i))return{success:!0,message:"No pre-commit hook found to uninstall."};try{if(!A.readFileSync(i,"utf8").includes(ne))return{success:!1,message:"Existing pre-commit hook is not managed by Secret Leak Detector; refusing to delete user hook."};if(A.existsSync(n)){let o=A.readFileSync(n,"utf8").trim();if(o&&A.existsSync(o))return A.copyFileSync(o,i),A.unlinkSync(o),A.unlinkSync(n),{success:!0,message:"Uninstalled SLD hook and restored original pre-commit hook."}}return A.unlinkSync(i),{success:!0,message:"Removed Secret Leak Detector pre-commit hook."}}catch(s){return{success:!1,message:`Failed to uninstall hook: ${s.message}`}}}};var L;function wt(t){L=f.window.createOutputChannel("Secret Leak Detector"),t.subscriptions.push(L),L.appendLine("\u{1F510} [Secret Leak Detector] Extension activated.");let e=new ae;t.subscriptions.push(e),t.subscriptions.push(f.languages.registerCodeActionsProvider({scheme:"file"},new W(e),{providedCodeActionKinds:W.providedCodeActionKinds}));let i=new ce,n=new de;f.window.registerTreeDataProvider("secret-leak-detector.findingsView",i),f.window.registerTreeDataProvider("secret-leak-detector.overviewView",n);let s=f.workspace.workspaceFolders?.[0],o=s?s.uri.fsPath:process.cwd(),r=new pe(o);e.onFindingsChanged(a=>{i.updateFindings(a),n.update(a.length,!0),K.currentPanel&&K.currentPanel.updateFindings(a)});let c=()=>f.workspace.getConfiguration("secretLeakDetector");function d(){let u=c().get("minEntropy");e.setMinEntropy(typeof u=="number"&&u>0?u:void 0);let g=t.workspaceState.get("ignoredFindings",[]);e.setIgnoredFindings(g)}d();let l=ot.join(t.extensionPath,"dist","cli.js");rt.existsSync(l)&&r.ensureHookIsPinned(l).catch(()=>{}),t.subscriptions.push(f.workspace.onDidChangeConfiguration(a=>{a.affectsConfiguration("secretLeakDetector")&&(d(),f.window.activeTextEditor&&e.scanDocument(f.window.activeTextEditor.document))})),f.window.activeTextEditor&&e.scanDocument(f.window.activeTextEditor.document),t.subscriptions.push(f.workspace.onDidSaveTextDocument(a=>{c().get("enableRealtimeScanning",!0)&&e.scanDocument(a)})),t.subscriptions.push(f.workspace.onDidOpenTextDocument(a=>{c().get("enableRealtimeScanning",!0)&&e.scanDocument(a)}));let m=new Map;t.subscriptions.push(f.workspace.onDidChangeTextDocument(a=>{if(!c().get("enableRealtimeScanning",!0))return;let u=a.document.uri.toString(),g=m.get(u);g&&clearTimeout(g);let h=setTimeout(()=>{e.scanDocument(a.document),m.delete(u)},350);m.set(u,h)})),t.subscriptions.push(f.workspace.onDidDeleteFiles(a=>{a.files.forEach(u=>e.removeDocument(u))})),t.subscriptions.push(f.commands.registerCommand("secret-leak-detector.scanWorkspace",async()=>{await f.window.withProgress({location:f.ProgressLocation.Notification,title:"\u{1F510} Scanning workspace for secret leaks...",cancellable:!1},async a=>{let g=`{${c().get("excludeGlobs",[]).join(",")}}`,h=1e3,p=await f.workspace.findFiles("**/*",g,h),v=[],b=0,S=0;for(let R of p)try{if((await f.workspace.fs.stat(R)).size>5*1024*1024){S++;continue}let F=await f.workspace.openTextDocument(R),j=e.scanDocument(F);v.push(...j),b++}catch{S++}let C=p.length>=h,y=`Scanned ${b} files.`;if(C&&(y+=` \u26A0\uFE0F Scan was capped at ${h} files.`),S>0&&(y+=` (${S} large or binary files skipped)`),v.length===0)f.window.showInformationMessage(`\u2705 Scan complete: ${y} No secrets or credentials detected!`);else{let R=v.filter(x=>x.risk==="CRITICAL").length;f.window.showErrorMessage(`\u{1F6A8} Found ${v.length} leaked secret(s) (${R} Critical)! ${y}`,"Open Dashboard","View Findings").then(x=>{x==="Open Dashboard"?f.commands.executeCommand("secret-leak-detector.openDashboard"):x==="View Findings"&&f.commands.executeCommand("workbench.view.extension.secret-leak-detector-sidebar")})}})})),t.subscriptions.push(f.commands.registerCommand("secret-leak-detector.scanStaged",async()=>{L.clear(),L.appendLine("\u{1F510} [Secret Leak Detector] Scanning Git staged changes..."),L.show(!0);let a=c().get("blockGitCommits",!0),u=await r.scanStagedChanges();if(u.status==="ERROR"){L.appendLine(`\u274C [Secret Leak Detector] Scan error: ${u.error}`),a?f.window.showErrorMessage(`\u274C COMMIT GATE BLOCKED: Git security scan failed (${u.error}). Failing closed for safety.`,"View Output"):f.window.showWarningMessage(`\u26A0\uFE0F Git scan encountered an error: ${u.error}`);return}if(u.status==="CLEAN"){L.appendLine("\u2705 All staged changes are clean! No credentials detected."),f.window.showInformationMessage("\u2705 Git staged changes are safe to commit.");return}let g=u.findings,h=g.filter(S=>et(S.risk,O)),p=r.formatTerminalBlockedMessage(h.length>0?h:g);L.appendLine(p);let b=a&&h.length>0?`\u274C COMMIT BLOCKED: ${h.length} secret(s) at or above ${O} detected in staged changes!`:`\u26A0\uFE0F WARNING: ${g.length} secret(s) detected in staged changes (none block at the ${O} threshold).`;f.window.showErrorMessage(b,"Open Dashboard","View Output").then(S=>{S==="Open Dashboard"&&K.createOrShow(t.extensionUri,g)})})),t.subscriptions.push(f.commands.registerCommand("secret-leak-detector.openDashboard",()=>{K.createOrShow(t.extensionUri,e.getAllFindings())})),t.subscriptions.push(f.commands.registerCommand("secret-leak-detector.installGitHook",async()=>{let a=await r.installPreCommitHook();a.success?f.window.showInformationMessage(`\u{1F6E1}\uFE0F ${a.message}`):f.window.showErrorMessage(`Failed to install hook: ${a.message}`)})),t.subscriptions.push(f.commands.registerCommand("secret-leak-detector.uninstallGitHook",async()=>{let a=await r.uninstallPreCommitHook();a.success?f.window.showInformationMessage(`\u{1F6E1}\uFE0F ${a.message}`):f.window.showErrorMessage(`Failed to uninstall hook: ${a.message}`)})),t.subscriptions.push(f.commands.registerCommand("secret-leak-detector.ignoreFinding",async a=>{let u=a;if(!u){let h=e.getAllFindings();if(h.length===0){f.window.showInformationMessage("No active findings to ignore.");return}let p=await f.window.showQuickPick(h.map(v=>({label:`${v.type} (${v.file}:${v.line})`,description:v.redactedSecret,id:v.id})),{placeHolder:"Select a finding to ignore (suppress as false-positive)"});if(!p)return;u=p.id}e.ignoreFinding(u);let g=e.getIgnoredFindings();await t.workspaceState.update("ignoredFindings",g),f.window.showInformationMessage("\u{1F6E1}\uFE0F Finding marked as false-positive and suppressed.")})),t.subscriptions.push(f.commands.registerCommand("secret-leak-detector.remediateFinding",async(a,u,g)=>{await W.executeRemediation(a,u,g)})),t.subscriptions.push(f.commands.registerCommand("secret-leak-detector.clearFindings",()=>{e.clear(),f.window.showInformationMessage("Secret Leak Detector: All findings cleared.")})),r.isGitRepo().then(a=>{n.update(0,a)})}function Rt(){L&&L.dispose()}0&&(module.exports={activate,deactivate});
