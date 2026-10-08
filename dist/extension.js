"use strict";var Ee=Object.create;var T=Object.defineProperty;var Ce=Object.getOwnPropertyDescriptor;var Ie=Object.getOwnPropertyNames;var xe=Object.getPrototypeOf,we=Object.prototype.hasOwnProperty;var _e=(t,e)=>{for(var n in e)T(t,n,{get:e[n],enumerable:!0})},j=(t,e,n,i)=>{if(e&&typeof e=="object"||typeof e=="function")for(let s of Ie(e))!we.call(t,s)&&s!==n&&T(t,s,{get:()=>e[s],enumerable:!(i=Ce(e,s))||i.enumerable});return t};var S=(t,e,n)=>(n=t!=null?Ee(xe(t)):{},j(e||!t||!t.__esModule?T(n,"default",{value:t,enumerable:!0}):n,t)),Re=t=>j(T({},"__esModule",{value:!0}),t);var Oe={};_e(Oe,{activate:()=>Ne,deactivate:()=>Me});module.exports=Re(Oe);var f=S(require("vscode"));var b=S(require("vscode"));var J=[{id:"aws-access-key",name:"AWS Access Key ID",provider:"Amazon Web Services",pattern:/\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b/g,baseConfidence:98,baseRiskWeight:95,signals:["AWS IAM standard 20-character key prefix (AKIA/ASIA/ABIA/ACCA)","Deterministic uppercase alphanumeric structure","Direct cloud resource control & hijacking capability"],suggestedEnvName:()=>"AWS_ACCESS_KEY_ID",remediationInstructions:["Revoke the exposed Access Key ID immediately in AWS IAM Management Console.","Check AWS CloudTrail logs for unauthorized API calls originated by this key.","Transition to IAM Roles for Amazon EC2 or AWS IAM Identity Center (SSO).","Never store access keys in source code; use AWS_ACCESS_KEY_ID environment variable."]},{id:"aws-secret-key",name:"AWS Secret Access Key",provider:"Amazon Web Services",pattern:/(?:aws_secret_access_key|aws_secret_key|secret_access_key)\s*[:=]\s*["']([A-Za-z0-9/+=]{40})["']/gi,baseConfidence:94,baseRiskWeight:95,minEntropy:4.1,signals:["Contextual AWS credential parameter match","High-entropy 40-character Base64 payload","Pairs with AWS Access Key for root/IAM API authentication"],suggestedEnvName:()=>"AWS_SECRET_ACCESS_KEY",remediationInstructions:["Rotate the key pair immediately in the AWS IAM Console.","Audit AWS KMS and S3 bucket accesses during exposure window.","Store secrets in AWS Secrets Manager or Parameter Store."]},{id:"github-pat",name:"GitHub Personal Access Token",provider:"GitHub",pattern:/\b(gh[pousr]_[A-Za-z0-9_]{36,255}|github_pat_[A-Za-z0-9_]{82})\b/g,baseConfidence:99,baseRiskWeight:95,signals:["Official GitHub token format prefix (ghp_, gho_, ghu_, ghs_, github_pat_)","Deterministic token structure and length","Permits repository code modification, workflow execution, or release poisoning"],suggestedEnvName:()=>"GITHUB_TOKEN",remediationInstructions:["Revoke token immediately at https://github.com/settings/tokens.","Check GitHub Security Audit Log for unauthorized repository clones or writes.","Use GitHub fine-grained PATs with scoped repository permissions.","Use GitHub Actions secrets rather than personal tokens for CI/CD."]},{id:"google-api-key",name:"Google Cloud / Gemini API Key",provider:"Google Cloud",pattern:/\b(AIza[0-9A-Za-z_-]{34,35})\b/g,baseConfidence:96,baseRiskWeight:90,minEntropy:3.5,signals:["Google standard AIza service key signature","Fixed 39-character alphanumeric structure","Access to Google Cloud Platform APIs and billing services"],suggestedEnvName:()=>"GEMINI_API_KEY",remediationInstructions:["Restrict or delete the API key in Google Cloud Console Credentials page.","Apply API restrictions (e.g. restrict solely to Generative Language API).","Apply HTTP referrer or IP address restrictions.","Store in GEMINI_API_KEY environment variable."]},{id:"openai-api-key",name:"OpenAI API Key",provider:"OpenAI",pattern:/\b(sk-proj-[A-Za-z0-9_-]{48,}|sk-[A-Za-z0-9]{32,48})\b/g,baseConfidence:97,baseRiskWeight:92,minEntropy:4,signals:["OpenAI official secret prefix (sk-proj- or sk-)","High Shannon entropy key payload","Direct account credit exhaustion and model theft risk"],suggestedEnvName:()=>"OPENAI_API_KEY",remediationInstructions:["Revoke key at https://platform.openai.com/api-keys.","Verify credit consumption in OpenAI usage dashboard.","Inject credentials using OPENAI_API_KEY environment variable."]},{id:"anthropic-api-key",name:"Anthropic Claude API Key",provider:"Anthropic",pattern:/\b(sk-ant-[A-Za-z0-9_-]{40,})\b/g,baseConfidence:98,baseRiskWeight:92,minEntropy:3.8,signals:["Anthropic official secret token signature (sk-ant-)","High entropy cryptographic token payload","Direct Claude model API billing access"],suggestedEnvName:()=>"ANTHROPIC_API_KEY",remediationInstructions:["Revoke the API key in Anthropic Console.","Generate replacement key with spend limit configured.","Inject via ANTHROPIC_API_KEY environment variable."]},{id:"stripe-secret-key",name:"Stripe Secret Key",provider:"Stripe",pattern:/\b((?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,34})\b/g,baseConfidence:97,baseRiskWeight:96,signals:["Stripe signature prefix (sk_live / rk_live / sk_test)","Financial transaction and customer credit card access","High financial liability and compliance breach"],suggestedEnvName:()=>"STRIPE_SECRET_KEY",remediationInstructions:["Roll API key immediately in Stripe Dashboard > Developers > API keys.","Audit recent transactions and payout bank account modifications.","Never bundle Stripe secret keys in frontend or mobile client builds."]},{id:"slack-bot-token",name:"Slack OAuth / Bot Token",provider:"Slack",pattern:/\b(xox[baprs]-[0-9A-Za-z-]{10,72})\b/g,baseConfidence:95,baseRiskWeight:82,signals:["Slack OAuth bot/user prefix (xoxb/xoxp/xoxa)","Internal company communications and workspace access"],suggestedEnvName:()=>"SLACK_BOT_TOKEN",remediationInstructions:["Revoke token in api.slack.com/apps.","Re-install app with minimal necessary OAuth scopes."]},{id:"slack-webhook",name:"Slack Incoming Webhook URL",provider:"Slack",pattern:/(https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9_]{8,12}\/B[A-Z0-9_]{8,12}\/[A-Za-z0-9_]{24})/g,baseConfidence:98,baseRiskWeight:78,signals:["Slack Incoming Webhook URL structure","Enables unauthorized message spoofing and channel phishing"],suggestedEnvName:()=>"SLACK_WEBHOOK_URL",remediationInstructions:["Delete the exposed webhook URL in Slack App settings.","Generate a new webhook URL and store in SLACK_WEBHOOK_URL."]},{id:"azure-storage-key",name:"Azure Shared Storage Key",provider:"Microsoft Azure",pattern:/(?:AccountKey|azure_secret|azure_key)\s*[:=]\s*["']([A-Za-z0-9/+=]{86,88}==)["']/gi,baseConfidence:93,baseRiskWeight:90,minEntropy:4.2,signals:["Azure storage account key signature (86-88 chars base64 with == padding)","Full administrative access to Azure Blob/Queue/Table storage"],suggestedEnvName:()=>"AZURE_STORAGE_KEY",remediationInstructions:["Regenerate storage key in Azure Portal.","Adopt Azure Managed Identity or Microsoft Entra ID authentication instead."]},{id:"private-key",name:"Cryptographic Private Key (PEM)",provider:"Cryptography",pattern:/(-----BEGIN (?:RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----[\s\S]*?-----END (?:RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----)/g,baseConfidence:100,baseRiskWeight:100,signals:["Standard PEM container header and footer","Unencrypted cryptographic private key","Total server impersonation, SSH compromise, or TLS decryption risk"],suggestedEnvName:()=>"PRIVATE_KEY_PATH",remediationInstructions:["Immediately decommission this private key pair.","Remove public key counterpart from all servers authorized_keys.","Never commit private keys to version control; use SSH agents or secret vaults."]},{id:"database-url",name:"Database Connection String with Credentials",provider:"Database",pattern:/\b((?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis):\/\/[^:\s'"]+:([^@\s'"]+)@[a-zA-Z0-9.-]+(?::[0-9]+)?\/[^\s'"]+)/gi,baseConfidence:92,baseRiskWeight:88,minEntropy:3.2,signals:["Database connection URL containing embedded user:password credentials","Direct data exfiltration, deletion, or ransomware risk"],suggestedEnvName:()=>"DATABASE_URL",remediationInstructions:["Rotate the database user password immediately on the database server.","Migrate connection string to DATABASE_URL environment variable.","Enable SSL/TLS requirement and VPC network access controls."]},{id:"jwt-token",name:"JSON Web Token (JWT)",provider:"Auth / Identity",pattern:/\b(ey[A-Za-z0-9_-]{15,}\.ey[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{10,})\b/g,baseConfidence:88,baseRiskWeight:75,minEntropy:4.1,signals:["Header.Payload.Signature Base64 tripartite JWT structure","Authentication session hijacking and privilege escalation"],suggestedEnvName:t=>t?.toUpperCase()||"AUTH_TOKEN",remediationInstructions:["Invalidate active sessions / revoke refresh token family in identity provider.","Never hardcode tokens in client or backend source repositories."]},{id:"generic-api-key",name:"Generic API Secret Assignment",provider:"Generic Credential",pattern:/(?:(?:api_?key|secret_?key|auth_?token|client_?secret|access_?token|private_?key)\s*[:=]\s*["']([A-Za-z0-9_.~-]{20,90})["'])/gi,baseConfidence:80,baseRiskWeight:70,minEntropy:3.5,signals:["Sensitive identifier keyword assignment","High Shannon entropy string literal"],suggestedEnvName:t=>t?t.toUpperCase():"API_KEY",remediationInstructions:["Identify corresponding API provider and rotate credential.","Migrate credential to local .env file (ensure .env is in .gitignore)."]}];var P=S(require("path")),q=[/api[_-]?key/i,/secret[_-]?key/i,/access[_-]?token/i,/auth[_-]?token/i,/private[_-]?key/i,/client[_-]?secret/i,/password/i,/credential/i,/session[_-]?token/i,/bearer/i,/aws[_-]?(?:access|secret)/i,/stripe[_-]?(?:secret|key)/i,/github[_-]?(?:token|pat)/i,/slack[_-]?token/i,/db[_-]?pass(?:word)?/i],Te=[/example/i,/placeholder/i,/mock/i,/dummy/i,/fake/i,/sample/i,/test[_-]?(?:key|token|id)/i,/demo/i,/insert[_-]?here/i];function X(t){let e=t.replace(/\\/g,"/").toLowerCase(),n=P.basename(t).toLowerCase(),i=P.extname(t).toLowerCase(),s=/(?:^|\/)(?:test|tests|spec|specs|__tests__|__mocks__|fixtures|mocks)\/|(?:test|spec)\.[a-z0-9]+$/i.test(e),r=/(?:^|\/)(?:docs|doc|documentation|tutorials|guides)\/|readme\.md|contributing\.md|changelog\.md/i.test(e),c=/(?:example|sample|\.example|\.sample)/i.test(e),a=/^\.env(?:\.[a-z0-9]+)?$/.test(n)||/(?:config|settings|secret|credential|database|deploy|production|staging|k8s|helm|tfvars)/i.test(e)||[".env",".yaml",".yml",".json",".toml",".ini",".tf"].includes(i),o=/^\.env/.test(n)||/(?:secret|credential|id_rsa|private_key|keypair|auth_config)/i.test(n);return{fileExtension:i,isConfig:a,isTest:s,isDoc:r,isSensitiveName:o,isExampleOrSample:c}}function Q(t,e){let n=t[e]||"",i=[];for(let g=Math.max(0,e-3);g<e;g++)i.push(t[g]);let s=[];for(let g=e+1;g<=Math.min(t.length-1,e+3);g++)s.push(t[g]);let r=n.match(/(?:const|let|var|val|\$|string|final)\s+([a-zA-Z0-9_]+)/i)||n.match(/([a-zA-Z0-9_]+)\s*[:=]/i),c=r?r[1]:void 0,a=!1,o=!1;c?(a=q.some(g=>g.test(c)),o=Te.some(g=>g.test(c))):a=q.some(g=>g.test(n));let d=/[:=]/.test(n),u=/(?:process\.env|os\.getenv|os\.environ|dotenv|config\.get)/i.test(n),m=/(?:authorization|bearer|x-api-key)/i.test(n),l=/^\s*(?:\/\/|#|\/\*|\*|--)/.test(n);return{inferredVariable:c,isSensitiveIdentifier:a,isBenignIdentifier:o,isAssignment:d,isEnvOrConfigAccess:u,isHeaderOrBearer:m,isInComment:l,surroundingBefore:i,matchedLine:n,surroundingAfter:s}}var Pe=/(?:api_?key|secret|token|password|auth|credential|access_?key|private_?key)/i,De=/(?:console\.(?:log|warn|error|info|debug)|logger\.|print\(|logging\.)/i;function ee(t,e){let n=t[e]||"",i=De.test(n),s=/(?:process\.env\.[A-Za-z0-9_]+|os\.(?:getenv|environ\.get)\([^)]+\))\s*\|\|\s*["'][^"']+["']/.test(n),r=/(?:authorization|x-api-key|bearer)\s*[:=]/i.test(n),c=n.match(/([a-zA-Z0-9_$.]+)\s*[:=]\s*["'][^"']+["']/)||n.match(/["']([a-zA-Z0-9_.]+)["']\s*:\s*["'][^"']+["']/),a,o=!1;c&&(a=c[1],o=Pe.test(a));let d="UNKNOWN";return s?d="ENV_FALLBACK":r?d="HEADER":a&&a.includes(".")?d="OBJECT_PROPERTY":a?d="VARIABLE_DECLARATION":i&&(d="FUNCTION_ARG"),{variablePath:a,isSensitiveProperty:o,isEnvFallback:s,isAuthorizationHeader:r,isLoggingCall:i,scopeType:d}}function B(t){if(!t||t.length===0)return 0;let e={};for(let s of t)e[s]=(e[s]||0)+1;let n=0,i=t.length;for(let s in e){let r=e[s]/i;n-=r*Math.log2(r)}return Math.round(n*100)/100}function K(t){return/^[0-9a-fA-F]+$/.test(t)?{setName:"HEX",baseSize:16}:/^[A-Za-z0-9+/=_-]+$/.test(t)?{setName:"BASE64",baseSize:64}:/^[A-Za-z0-9]+$/.test(t)?{setName:"ALPHANUMERIC",baseSize:62}:/^[\x20-\x7E]+$/.test(t)?{setName:"ASCII_PRINTABLE",baseSize:95}:{setName:"SPECIAL",baseSize:128}}function te(t){if(!t||t.length===0)return 0;let e=B(t),{baseSize:n}=K(t),i=Math.log2(n);if(i<=0)return 0;let s=Math.min(1,e/i);return Math.round(s*100)/100}var ie=[/example/i,/placeholder/i,/your[_-]?(?:api)?[_-]?key/i,/your[_-]?secret/i,/your[_-]?token/i,/insert[_-]?here/i,/replace[_-]?me/i,/enter[_-]?your/i,/change[_-]?me/i,/dummy/i,/fake[_-]?token/i,/xxxx+/i,/test[_-]?value/i,/AKIAIOSFODNN7EXAMPLE/i,/wJalrXUtnFEMI\/K7MDENG\/bPxRfiCYEXAMPLEKEY/i,/^123456789[0-9]*$/,/^abcdef[a-z0-9]*$/i,/00000000[0-9]*/,/sk_live_example/i,/ghp_example/i,/:\/\/[^:]+:(?:password|secret|changeme|pass|admin|test)@/i,/:password@/i],Fe=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;function ne(t,e,n){for(let s of ie)if(s.test(t))return{isFalsePositive:!0,reason:`Matched known documentation/placeholder pattern: ${s.source}`,confidencePenalty:100};if(e){for(let s of ie)if(s.test(e))return{isFalsePositive:!0,reason:`Variable identifier indicates placeholder: ${e}`,confidencePenalty:100}}let i=new Set(t.split("")).size;if(t.length>=10&&i<=3)return{isFalsePositive:!0,reason:"Low character diversity (repetitive filler characters)",confidencePenalty:95};if(Fe.test(t)&&!e?.match(/secret|token|api_?key/i))return{isFalsePositive:!0,reason:"Standard UUID identifier without credential context",confidencePenalty:90};if(n){let s=/(?:docs|documentation|tutorials|guides)\/|readme\.md/i.test(n);if(/(?:example|sample|\.example|\.sample)/i.test(n)&&/example|your_/i.test(t))return{isFalsePositive:!0,reason:"Sample configuration value inside template/example file",confidencePenalty:90};if(s&&!t.startsWith("ghp_")&&!t.startsWith("AKIA"))return{isFalsePositive:!1,confidencePenalty:25}}return{isFalsePositive:!1,confidencePenalty:0}}function se(t){if(!/^(AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}$/.test(t))return{isValid:!1,confidenceBonus:0,reason:"Invalid AWS key length or character set"};let e=t.substring(0,4);return{isValid:!0,confidenceBonus:10,reason:{AKIA:"Standard permanent IAM user access key",ASIA:"Temporary STS session access key",ABIA:"AWS Backup access key",ACCA:"AWS CodeCommit access key"}[e]||"Valid AWS Access Key ID structure"}}function oe(t){let e=/^sk_live_[0-9a-zA-Z]{24,34}$/.test(t)||/^rk_live_[0-9a-zA-Z]{24,34}$/.test(t),n=/^sk_test_[0-9a-zA-Z]{24,34}$/.test(t)||/^rk_test_[0-9a-zA-Z]{24,34}$/.test(t);return!e&&!n?{isValid:!1,confidenceBonus:0,reason:"Does not match official Stripe secret key format"}:{isValid:!0,confidenceBonus:e?12:5,reason:e?"Production live Stripe Secret Key":"Stripe Test API key"}}function re(t){return/^ghp_[A-Za-z0-9_]{36}$/.test(t)?{isValid:!0,confidenceBonus:12,reason:"GitHub Personal Access Token (Classic)"}:/^gho_[A-Za-z0-9_]{36}$/.test(t)?{isValid:!0,confidenceBonus:10,reason:"GitHub OAuth Access Token"}:/^ghs_[A-Za-z0-9_]{36}$/.test(t)?{isValid:!0,confidenceBonus:10,reason:"GitHub Server-to-server token"}:/^github_pat_[A-Za-z0-9_]{82}$/.test(t)?{isValid:!0,confidenceBonus:15,reason:"GitHub Fine-Grained Personal Access Token"}:{isValid:!1,confidenceBonus:0,reason:"Invalid GitHub token prefix or length"}}function ae(t){let e=t.split(".");if(e.length!==3)return{isValid:!1,confidenceBonus:0,reason:"Not a 3-part dot-separated JWT"};try{let n=Buffer.from(e[0],"base64url").toString("utf8"),i=JSON.parse(n);if(i&&typeof i=="object"&&i.alg)return{isValid:!0,confidenceBonus:15,reason:`Valid JWT structure with signature algorithm: ${i.alg}`}}catch{}return{isValid:!1,confidenceBonus:0,reason:"Malformed JWT header JSON payload"}}function ce(t){try{let e=new URL(t);if(!["postgres:","postgresql:","mysql:","mongodb:","redis:"].includes(e.protocol))return{isValid:!1,confidenceBonus:0,reason:"Unsupported database protocol scheme"};if(e.password&&e.password.length>0)return{isValid:!0,confidenceBonus:12,reason:`Database connection string containing credentials for user '${e.username||"default"}'`}}catch{}return{isValid:!1,confidenceBonus:0,reason:"Invalid database connection URL structure"}}function de(t,e,n,i,s,r){let c=[],a=t.baseConfidence;c.push({signal:"KNOWN_PATTERN_MATCH",description:`Matched recognized credential signature for ${t.provider} (${t.name})`,confidenceImpact:0,details:{ruleId:t.id,provider:t.provider}});let o=B(e),d=te(e),{setName:u}=K(e);if(o>=4.5?(a=Math.min(100,a+5),c.push({signal:"HIGH_ENTROPY",description:`Cryptographic entropy: ${o} bits/char (${u} set), indicates non-human randomness`,confidenceImpact:5,details:{shannonEntropy:o,normalizedEntropy:d,characterSet:u}})):o>=3.4?c.push({signal:"MODERATE_ENTROPY",description:`Moderate entropy: ${o} bits/char (${u} set)`,confidenceImpact:0,details:{shannonEntropy:o,normalizedEntropy:d,characterSet:u}}):t.minEntropy&&o<t.minEntropy&&(a=Math.max(10,a-30),c.push({signal:"LOW_ENTROPY",description:`Low entropy score: ${o} bits/char below minimum threshold of ${t.minEntropy}`,confidenceImpact:-30,details:{shannonEntropy:o,minEntropy:t.minEntropy}})),i.isSensitiveIdentifier||r?.isSensitiveProperty){let y=r?.variablePath||i.inferredVariable||"credential";a=Math.min(100,a+10),c.push({signal:"SENSITIVE_IDENTIFIER",description:`Assigned to sensitive identifier / property: '${y}'`,confidenceImpact:10,details:{identifier:y}})}else i.isBenignIdentifier&&(a=Math.max(10,a-25),c.push({signal:"BENIGN_IDENTIFIER",description:`Identifier name indicates mock or sample value: '${i.inferredVariable}'`,confidenceImpact:-25,details:{identifier:i.inferredVariable}}));r?.isEnvFallback&&(a=Math.min(100,a+12),c.push({signal:"ENV_FALLBACK_ASSIGNMENT",description:'Hardcoded literal provided as environment variable fallback (e.g. process.env.KEY || "...")',confidenceImpact:12})),r?.isAuthorizationHeader&&(a=Math.min(100,a+10),c.push({signal:"AUTHORIZATION_HEADER",description:"Passed in HTTP Authorization or Bearer token header context",confidenceImpact:10})),(n.isConfig||n.isSensitiveName)&&(a=Math.min(100,a+8),c.push({signal:"PRODUCTION_CONFIG_FILE",description:`Located in configuration or secret storage file (${n.fileExtension})`,confidenceImpact:8,details:{isConfig:n.isConfig,extension:n.fileExtension}})),n.isTest&&(a=Math.max(20,a-20),c.push({signal:"TEST_FILE_PENALTY",description:"Found inside test/mock directory structure",confidenceImpact:-20})),n.isDoc&&(a=Math.max(20,a-25),c.push({signal:"DOCUMENTATION_PENALTY",description:"Found inside documentation or markdown guide",confidenceImpact:-25}));let m;t.id==="aws-access-key"?m=se(e):t.id==="stripe-secret-key"?m=oe(e):t.id==="github-pat"?m=re(e):t.id==="jwt-token"?m=ae(e):t.id==="database-url"&&(m=ce(e)),m&&m.isValid&&(a=Math.min(100,a+m.confidenceBonus),c.push({signal:"STRUCTURAL_VALIDATION_PASSED",description:`Structural validation verified: ${m.reason}`,confidenceImpact:m.confidenceBonus}));let l=ne(e,i.inferredVariable,s);if(l.isFalsePositive)return{confidence:0,evidence:{items:[{signal:"KNOWN_PLACEHOLDER_REJECTED",description:l.reason||"Placeholder value rejected",confidenceImpact:-100}],shannonEntropy:o,normalizedEntropy:d,characterSet:u,surroundingCode:{before:i.surroundingBefore,targetLine:i.matchedLine,after:i.surroundingAfter,inferredVariable:i.inferredVariable},fileContext:{fileExtension:n.fileExtension,isConfig:n.isConfig,isTest:n.isTest,isDoc:n.isDoc,isSensitiveName:n.isSensitiveName,isExampleOrSample:n.isExampleOrSample}},isSuppressed:!0,suppressReason:l.reason};l.confidencePenalty>0&&(a=Math.max(10,a-l.confidencePenalty));let g=Math.max(0,Math.min(100,Math.round(a))),h={items:c,shannonEntropy:o,normalizedEntropy:d,characterSet:u,surroundingCode:{before:i.surroundingBefore,targetLine:i.matchedLine,after:i.surroundingAfter,inferredVariable:i.inferredVariable},fileContext:{fileExtension:n.fileExtension,isConfig:n.isConfig,isTest:n.isTest,isDoc:n.isDoc,isSensitiveName:n.isSensitiveName,isExampleOrSample:n.isExampleOrSample}};return{confidence:g,evidence:h,isSuppressed:!1}}function le(t,e,n,i){let s=[],r=0,c=Math.min(40,Math.round(t.baseRiskWeight/100*40));r+=c,s.push({factor:"CREDENTIAL_SEVERITY",weight:40,scoreContribution:c,explanation:`${t.provider} ${t.name} has high inherent privilege capability`});let a=Math.round(e/100*25);r+=a,s.push({factor:"CONFIDENCE_LEVEL",weight:25,scoreContribution:a,explanation:`Multi-signal verification confidence is ${e}%`});let o=5,d="Standard source code file";n.isConfig||n.isSensitiveName?(o=15,d="Located in sensitive deployment / environment configuration"):n.isTest?(o=0,d="Located in test / fixture codebase with reduced operational blast radius"):n.isDoc&&(o=0,d="Located in documentation context"),r+=o,s.push({factor:"STORAGE_ENVIRONMENT",weight:15,scoreContribution:o,explanation:d});let u=5,m="Found in local uncommitted working tree";i&&(i.isRemote?(u=20,m="Pushed to remote repository branch (external exposure risk)"):i.isPresentInHistory?(u=16,m=`Committed to Git history across ${i.branches.length||1} branch(es) (${i.exposureDurationDays} days exposure)`):i.isPresentInHead&&(u=12,m="Committed in current HEAD commit")),r+=u,s.push({factor:"EXPOSURE_REACH",weight:20,scoreContribution:u,explanation:m});let l=Math.max(0,Math.min(100,Math.round(r))),g="LOW";l>=76?g="CRITICAL":l>=51?g="HIGH":l>=26?g="MEDIUM":g="LOW";let h=$e(l,i),y=`${g} Risk (${l}/100) \u2014 ${t.name}. ${h.summary}`;return{score:l,tier:g,factors:s,blastRadius:h,summary:y}}function $e(t,e){let n=[],i=Math.round(t*.5),s=e?e.isPresentInHead:!0,r=e?e.isPresentInHistory:!1,c=e?.isPresentInHistory?1:0,a=e?.branches||["main"],o=a.length,d=e?.isRemote||!1,u=e?.exposureDurationDays||0;s&&(n.push("Active working tree contains exposed secret"),i+=15),r&&(n.push(`Git history contains commit records across ${o} branch(es)`),i+=20),d&&(n.push("Secret has been synchronized to remote tracking branches"),i+=25),u>7&&(n.push(`Exposure duration exceeds ${u} days without rotation`),i+=10),i=Math.max(0,Math.min(100,i));let m="CONTAINED";i>=75?m="SEVERE":i>=50?m="EXTENSIVE":i>=25?m="MODERATE":m="CONTAINED";let l=`Blast Radius: ${m} (${i}/100) \u2014 ${d?"Remote & history exposure":r?"Historical commit exposure":"Contained to local working tree"}`;return{level:m,score:i,workingTreeExposed:s,gitHistoryExposed:r,commitCount:c,branchCount:o,branches:a,remoteExposed:d,exposureDurationDays:u,summary:l,factors:n}}var pe=S(require("crypto"));function D(t){if(!t)return"";let e=t.length;if(e<=8)return"\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022";let n=Math.min(4,Math.floor(e/4)),i=Math.min(3,Math.floor(e/4)),s=Math.max(4,e-n-i),r=t.substring(0,n),c=t.substring(e-i),a="\u2022".repeat(Math.min(12,s));return`${r}${a}${c}`}function G(t){return pe.createHash("sha256").update(t).digest("hex").substring(0,16)}function me(t,e,n,i,s){let r=t.suggestedEnvName(s),c=`process.env.${r}`,a=D(e),o=[`1. Revoke / rotate credential immediately with provider: ${t.provider}`,`2. Migrate secret value to local .env file (${r})`,`3. Replace hardcoded literal in ${n} with ${c}`,"4. Verify .env is listed in .gitignore so it is never committed","5. If committed previously, purge from Git history using git-filter-repo or BFG","6. Rescan file and commit to verify exposure is eliminated"],d=`${r}="${e}"`,u=`${r}=your_${r.toLowerCase()}_here`,m=`git filter-repo --invert-paths --path "${n}"`,l=`--- a/${n}
+++ b/${n}
@@ -${i},1 +${i},1 @@
- ... "${a}" ...
+ ... ${c} ...`;return{steps:o,envVarName:r,replacementCode:c,envFileSnippet:d,envExampleSnippet:u,gitHistoryPurgeCommand:m,diffPreview:l}}function F(t,e,n={}){let i=typeof n=="string"?{workspaceRoot:n}:n,s=i.rules||J,r=i.workspaceRoot,c=t.split(/\r?\n/),a=X(e),o=[],d=t,u=/"([^"\r\n]{2,80})"\s*\+\s*"([^"\r\n]{10,120})"/g,m;for(;(m=u.exec(t))!==null;){let l=m[1]+m[2];d+=`
const _deobfuscated = "${l}";`}for(let l of s){l.pattern.lastIndex=0;let g;for(;(g=l.pattern.exec(d))!==null;){let h=g[1]||g[0],y=g.index,z=t.substring(0,y).split(/\r?\n/),R=z.length,he=z[z.length-1].length+1,U=Q(c,R-1),ve=ee(c,R-1),I=de(l,h,a,U,e,ve);if(I.isSuppressed||l.minEntropy&&I.evidence.shannonEntropy<l.minEntropy&&l.baseRiskWeight<90)continue;let W=e;r&&e.startsWith(r)&&(W=e.substring(r.length).replace(/^[\\/]+/,""));let Z=le(l,I.confidence,a),Y=me(l,h,W,R,U.inferredVariable),be=`sec_${G(h)}_${R}`,ke=G(h),ye=D(h),Ae={id:be,fingerprint:ke,type:l.name,provider:l.provider,file:W,fullPath:e,line:R,column:he,length:h.length,rawSecret:h,redactedSecret:ye,confidence:I.confidence,risk:Z.tier,riskAssessment:Z,evidence:I.evidence,remediation:Y,status:"ACTIVE",detectedAt:new Date().toISOString(),signals:I.evidence.items.map(Se=>Se.description),exampleFix:Y.replacementCode,entropy:I.evidence.shannonEntropy};o.push(Ae)}}return Le(o)}function Le(t){let e=[];for(let n of t){let i=e.findIndex(s=>s.file===n.file&&s.line===n.line&&(s.rawSecret.includes(n.rawSecret)||n.rawSecret.includes(s.rawSecret)));if(i===-1)e.push(n);else{let s=e[i];(s.provider==="Generic Credential"&&n.provider!=="Generic Credential"||n.confidence>s.confidence)&&(e[i]=n)}}return e}var $=class{diagnosticCollection;currentFindings=new Map;onFindingsChangedEmitter=new b.EventEmitter;onFindingsChanged=this.onFindingsChangedEmitter.event;constructor(){this.diagnosticCollection=b.languages.createDiagnosticCollection("secret-leak-detector")}getDiagnosticCollection(){return this.diagnosticCollection}getAllFindings(){let e=[];for(let n of this.currentFindings.values())e.push(...n);return e}clear(){this.diagnosticCollection.clear(),this.currentFindings.clear(),this.onFindingsChangedEmitter.fire([])}scanDocument(e){if(e.uri.scheme!=="file")return[];let n=e.getText(),i=b.workspace.getWorkspaceFolder(e.uri),s=i?i.uri.fsPath:void 0,r=F(n,e.uri.fsPath,s);this.currentFindings.set(e.uri.fsPath,r);let c=[];for(let a of r){let o=Math.max(0,a.line-1),d=Math.max(0,a.column-1),u=d+a.length,m=new b.Range(o,d,o,u),l=b.DiagnosticSeverity.Warning;a.risk==="CRITICAL"||a.risk==="HIGH"?l=b.DiagnosticSeverity.Error:a.risk==="LOW"&&(l=b.DiagnosticSeverity.Information);let g=new b.Diagnostic(m,`[Secret Leak Detector] ${a.type} detected! Confidence: ${a.confidence}%. ${a.remediation}`,l);g.code={value:a.id,target:b.Uri.parse("https://github.com/MokuLakshithReddy/Secret_Leak_Detector")},g.source="Secret Leak Detector",c.push(g)}return this.diagnosticCollection.set(e.uri,c),this.onFindingsChangedEmitter.fire(this.getAllFindings()),r}removeDocument(e){this.diagnosticCollection.delete(e),this.currentFindings.delete(e.fsPath),this.onFindingsChangedEmitter.fire(this.getAllFindings())}dispose(){this.diagnosticCollection.dispose(),this.onFindingsChangedEmitter.dispose()}};var k=S(require("vscode")),A=S(require("fs")),L=S(require("path")),w=class{static providedCodeActionKinds=[k.CodeActionKind.QuickFix];diagnosticProvider;constructor(e){this.diagnosticProvider=e}provideCodeActions(e,n,i){let s=[],r=i.diagnostics.filter(a=>a.source==="Secret Leak Detector");if(r.length===0)return s;let c=this.diagnosticProvider.getAllFindings();for(let a of r){let o=c.find(m=>m.fullPath===e.uri.fsPath&&m.line===a.range.start.line+1);if(!o)continue;let d=this.createMoveToEnvAction(e,a.range,o);s.push(d);let u=new k.CodeAction("Ignore this finding (False Positive)",k.CodeActionKind.QuickFix);u.command={command:"secret-leak-detector.ignoreFinding",title:"Ignore Finding",arguments:[o.id]},s.push(u)}return s}createMoveToEnvAction(e,n,i){let s=new k.CodeAction(`\u{1F6E1}\uFE0F Move ${i.type} to .env and replace with environment variable`,k.CodeActionKind.QuickFix);return s.isPreferred=!0,s.command={command:"secret-leak-detector.remediateFinding",title:"Move to .env",arguments:[e.uri,n,i]},s}static async executeRemediation(e,n,i){let s=k.workspace.getWorkspaceFolder(e);if(!s){k.window.showErrorMessage("No workspace folder found to save .env file.");return}let r=s.uri.fsPath,c=L.join(r,".env"),a=L.join(r,".gitignore"),o=i.remediation?.envVarName;o||(i.type.includes("AWS Access Key")?o="AWS_ACCESS_KEY_ID":i.type.includes("AWS Secret")?o="AWS_SECRET_ACCESS_KEY":i.type.includes("GitHub")?o="GITHUB_TOKEN":i.type.includes("OpenAI")?o="OPENAI_API_KEY":i.type.includes("Anthropic")?o="ANTHROPIC_API_KEY":i.type.includes("Stripe")?o="STRIPE_SECRET_KEY":i.type.includes("Slack")?o="SLACK_TOKEN":i.type.includes("Database")?o="DATABASE_URL":o=`${i.provider.replace(/[^a-zA-Z0-9]/g,"_").toUpperCase()}_API_KEY`);let d=`
${o}="${i.rawSecret}"
`;try{A.appendFileSync(c,d,"utf8")}catch(h){k.window.showErrorMessage(`Failed to write to .env: ${h}`);return}A.existsSync(a)?A.readFileSync(a,"utf8").includes(".env")||A.appendFileSync(a,`
# Credentials
.env
.env.*.local
`,"utf8"):A.writeFileSync(a,`# Credentials
.env
.env.*.local
`,"utf8");let u=L.join(r,".env.example"),m=`${o}=your_${o.toLowerCase()}_here
`;(!A.existsSync(u)||!A.readFileSync(u,"utf8").includes(o))&&A.appendFileSync(u,m,"utf8");let l=new k.WorkspaceEdit,g=`process.env.${o}`;l.replace(e,n,g),await k.workspace.applyEdit(l),k.window.showInformationMessage(`\u2705 Moved ${i.type} to .env (${o}) and protected in .gitignore!`)}};var p=S(require("vscode")),N=class{_onDidChangeTreeData=new p.EventEmitter;onDidChangeTreeData=this._onDidChangeTreeData.event;findings=[];updateFindings(e){this.findings=e,this._onDidChangeTreeData.fire()}getTreeItem(e){return e}getChildren(e){if(!e){if(this.findings.length===0){let s=new E("No Leaks Detected (Safe)",p.TreeItemCollapsibleState.None);return s.iconPath=new p.ThemeIcon("shield-check",new p.ThemeColor("testing.iconPassed")),s.description="Workspace is clean",Promise.resolve([s])}let n=["CRITICAL","HIGH","MEDIUM","LOW"],i=[];for(let s of n){let r=this.findings.filter(c=>c.risk===s).length;if(r>0){let c=new E(`${s} Risk (${r})`,p.TreeItemCollapsibleState.Expanded,s);s==="CRITICAL"?c.iconPath=new p.ThemeIcon("error",new p.ThemeColor("errorForeground")):s==="HIGH"?c.iconPath=new p.ThemeIcon("warning",new p.ThemeColor("editorWarning.foreground")):s==="MEDIUM"?c.iconPath=new p.ThemeIcon("info",new p.ThemeColor("editorInfo.foreground")):c.iconPath=new p.ThemeIcon("pass",new p.ThemeColor("testing.iconPassed")),i.push(c)}}return Promise.resolve(i)}if(e.contextValue){let n=e.contextValue,s=this.findings.filter(r=>r.risk===n).map(r=>{let c=new E(`${r.type}`,p.TreeItemCollapsibleState.None);return c.description=`${r.file}:${r.line}`,c.tooltip=new p.MarkdownString(`**${r.type}** (${r.provider})

- **Risk:** ${r.risk}
- **Confidence:** ${r.confidence}%
- **Entropy:** ${r.entropy} bits/char
- **Secret:** \`${r.redactedSecret}\`

*${r.remediation}*`),c.iconPath=new p.ThemeIcon("key"),c.command={command:"vscode.open",title:"Jump to Secret",arguments:[p.Uri.file(r.fullPath),{selection:new p.Range(r.line-1,r.column-1,r.line-1,r.column-1+r.length)}]},c});return Promise.resolve(s)}return Promise.resolve([])}},M=class{_onDidChangeTreeData=new p.EventEmitter;onDidChangeTreeData=this._onDidChangeTreeData.event;findingsCount=0;isGit=!0;update(e,n){this.findingsCount=e,this.isGit=n,this._onDidChangeTreeData.fire()}getTreeItem(e){return e}getChildren(){let e=[],n=new E(this.findingsCount===0?"Status: Protected":`Status: ${this.findingsCount} Leaks Active`,p.TreeItemCollapsibleState.None);n.iconPath=new p.ThemeIcon(this.findingsCount===0?"check":"alert",this.findingsCount===0?new p.ThemeColor("testing.iconPassed"):new p.ThemeColor("errorForeground")),e.push(n);let i=new E("Run Full Workspace Scan",p.TreeItemCollapsibleState.None);i.iconPath=new p.ThemeIcon("search"),i.command={command:"secret-leak-detector.scanWorkspace",title:"Scan Workspace"},e.push(i);let s=new E("Check Git Staged Changes",p.TreeItemCollapsibleState.None);s.iconPath=new p.ThemeIcon("git-commit"),s.command={command:"secret-leak-detector.scanStaged",title:"Scan Staged Changes"},e.push(s);let r=new E("Open Interactive Dashboard",p.TreeItemCollapsibleState.None);r.iconPath=new p.ThemeIcon("dashboard"),r.command={command:"secret-leak-detector.openDashboard",title:"Open Dashboard"},e.push(r);let c=new E("Install Pre-Commit Hook",p.TreeItemCollapsibleState.None);return c.iconPath=new p.ThemeIcon("terminal"),c.command={command:"secret-leak-detector.installGitHook",title:"Install Hook"},e.push(c),Promise.resolve(e)}},E=class extends p.TreeItem{constructor(e,n,i){super(e,n),this.contextValue=i}};var v=S(require("vscode")),x=class t{static currentPanel;static viewType="secretLeakDetectorDashboard";_panel;_extensionUri;_disposables=[];_findings=[];static createOrShow(e,n){let i=v.window.activeTextEditor?v.window.activeTextEditor.viewColumn:void 0;if(t.currentPanel){t.currentPanel._panel.reveal(i),t.currentPanel.updateFindings(n);return}let s=v.window.createWebviewPanel(t.viewType,"\u{1F510} Secret Leak Detector Dashboard",i||v.ViewColumn.One,{enableScripts:!0,retainContextWhenHidden:!0,localResourceRoots:[e]});t.currentPanel=new t(s,e,n)}constructor(e,n,i){this._panel=e,this._extensionUri=n,this._findings=i,this._update(),this._panel.onDidDispose(()=>this.dispose(),null,this._disposables),this._panel.webview.onDidReceiveMessage(async s=>{switch(s.command){case"scanWorkspace":v.commands.executeCommand("secret-leak-detector.scanWorkspace");return;case"scanStaged":v.commands.executeCommand("secret-leak-detector.scanStaged");return;case"installHook":v.commands.executeCommand("secret-leak-detector.installGitHook");return;case"openFile":if(s.file&&s.line){let r=await v.workspace.openTextDocument(v.Uri.file(s.file));await v.window.showTextDocument(r,{selection:new v.Range(s.line-1,0,s.line-1,0)})}return}},null,this._disposables)}updateFindings(e){this._findings=e,this._panel.webview.postMessage({command:"updateData",findings:this._findings}),this._update()}dispose(){for(t.currentPanel=void 0,this._panel.dispose();this._disposables.length;){let e=this._disposables.pop();e&&e.dispose()}}_update(){this._panel.webview.html=this._getHtmlForWebview()}_getHtmlForWebview(){return`<!DOCTYPE html>
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
</html>`}};var ge=require("child_process"),fe=require("util"),_=S(require("fs")),O=S(require("path"));var ue=(0,fe.promisify)(ge.exec),H=class{workspaceRoot;constructor(e){this.workspaceRoot=e}async isGitRepo(){try{return await ue("git rev-parse --is-inside-work-tree",{cwd:this.workspaceRoot}),!0}catch{return!1}}async scanStagedChanges(){if(!await this.isGitRepo())return[];try{let{stdout:e}=await ue("git diff --cached --unified=0",{cwd:this.workspaceRoot});if(!e||e.trim().length===0)return[];let n=[],i=e.split(/^diff --git /m);for(let s of i){if(!s.trim())continue;let r=s.match(/^[ab]\/(.+?) [ab]\/(.+)/m)||s.match(/^\+\+\+ b\/(.+)/m),c=r?r[1]:"staged-file",a=O.join(this.workspaceRoot,c),o=s.split(`
`).filter(d=>d.startsWith("+")&&!d.startsWith("+++")).map(d=>d.substring(1)).join(`
`);if(o.trim()){let d=F(o,a,this.workspaceRoot);n.push(...d)}}return n}catch(e){return console.error("Failed to run git diff --cached:",e),[]}}formatTerminalBlockedMessage(e){let i=e.filter(o=>o.risk==="CRITICAL")[0]||e[0],s=typeof i.remediation=="string"?i.remediation:i.remediation?.steps?.join(`
`)||"Rotate and move to .env",r=i.evidence?.items?.map(o=>`  - [${o.confidenceImpact>=0?"+":""}${o.confidenceImpact}] ${o.description}`).join(`
`)||i.signals?.map(o=>`  - ${o}`).join(`
`)||"  - Known pattern match",c=i.riskAssessment?.blastRadius?`${i.riskAssessment.blastRadius.level} (${i.riskAssessment.blastRadius.summary})`:"Local Working Tree";return`
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
\u2022 Blast Radius: ${c}

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
`}async installPreCommitHook(){if(!await this.isGitRepo())return{success:!1,message:"Workspace is not a Git repository."};let e=O.join(this.workspaceRoot,".git","hooks");if(!_.existsSync(e))try{_.mkdirSync(e,{recursive:!0})}catch(s){return{success:!1,message:`Could not create .git/hooks directory: ${s}`}}let n=O.join(e,"pre-commit"),i=`#!/bin/sh
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
`;try{return _.writeFileSync(n,i,{mode:493}),{success:!0,message:`Pre-commit hook successfully installed to ${n}`}}catch(s){return{success:!1,message:`Failed to write hook file: ${s}`}}}};var C;function Ne(t){C=f.window.createOutputChannel("Secret Leak Detector"),t.subscriptions.push(C),C.appendLine("\u{1F510} [Secret Leak Detector] Extension activated.");let e=new $;t.subscriptions.push(e),t.subscriptions.push(f.languages.registerCodeActionsProvider({scheme:"file"},new w(e),{providedCodeActionKinds:w.providedCodeActionKinds}));let n=new N,i=new M;f.window.registerTreeDataProvider("secret-leak-detector.findingsView",n),f.window.registerTreeDataProvider("secret-leak-detector.overviewView",i);let s=f.workspace.workspaceFolders?.[0],r=s?s.uri.fsPath:process.cwd(),c=new H(r);e.onFindingsChanged(o=>{n.updateFindings(o),i.update(o.length,!0),x.currentPanel&&x.currentPanel.updateFindings(o)});let a=f.workspace.getConfiguration("secretLeakDetector");a.get("enableRealtimeScanning",!0)&&(f.window.activeTextEditor&&e.scanDocument(f.window.activeTextEditor.document),t.subscriptions.push(f.workspace.onDidSaveTextDocument(o=>{e.scanDocument(o)})),t.subscriptions.push(f.workspace.onDidOpenTextDocument(o=>{e.scanDocument(o)})),t.subscriptions.push(f.workspace.onDidCloseTextDocument(o=>{e.removeDocument(o.uri)}))),t.subscriptions.push(f.commands.registerCommand("secret-leak-detector.scanWorkspace",async()=>{await f.window.withProgress({location:f.ProgressLocation.Notification,title:"\u{1F510} Scanning workspace for secret leaks...",cancellable:!1},async o=>{let u=`{${a.get("excludeGlobs",[]).join(",")}}`,m=await f.workspace.findFiles("**/*",u,1e3),l=[],g=0;for(let h of m)try{let y=await f.workspace.openTextDocument(h),V=e.scanDocument(y);l.push(...V),g++}catch{}if(l.length===0)f.window.showInformationMessage(`\u2705 Scan complete: Scanned ${g} files. No secrets or credentials detected!`);else{let h=l.filter(y=>y.risk==="CRITICAL").length;f.window.showErrorMessage(`\u{1F6A8} Found ${l.length} leaked secret(s) (${h} Critical)! Commits may be blocked.`,"Open Dashboard","View Findings").then(y=>{y==="Open Dashboard"?f.commands.executeCommand("secret-leak-detector.openDashboard"):y==="View Findings"&&f.commands.executeCommand("workbench.view.extension.secret-leak-detector-sidebar")})}})})),t.subscriptions.push(f.commands.registerCommand("secret-leak-detector.scanStaged",async()=>{C.clear(),C.appendLine("\u{1F510} [Secret Leak Detector] Scanning Git staged changes..."),C.show(!0);let o=await c.scanStagedChanges();if(o.length===0)C.appendLine("\u2705 All staged changes are clean! No credentials detected."),f.window.showInformationMessage("\u2705 Git staged changes are safe to commit.");else{let d=c.formatTerminalBlockedMessage(o);C.appendLine(d),f.window.showErrorMessage(`\u274C COMMIT BLOCKED: ${o.length} secret(s) detected in staged changes!`,"Open Dashboard","View Output").then(u=>{u==="Open Dashboard"&&x.createOrShow(t.extensionUri,o)})}})),t.subscriptions.push(f.commands.registerCommand("secret-leak-detector.openDashboard",()=>{x.createOrShow(t.extensionUri,e.getAllFindings())})),t.subscriptions.push(f.commands.registerCommand("secret-leak-detector.installGitHook",async()=>{let o=await c.installPreCommitHook();o.success?f.window.showInformationMessage(`\u{1F6E1}\uFE0F ${o.message}`):f.window.showErrorMessage(`Failed to install hook: ${o.message}`)})),t.subscriptions.push(f.commands.registerCommand("secret-leak-detector.remediateFinding",async(o,d,u)=>{await w.executeRemediation(o,d,u)})),t.subscriptions.push(f.commands.registerCommand("secret-leak-detector.clearFindings",()=>{e.clear(),f.window.showInformationMessage("Secret Leak Detector: All findings cleared.")})),c.isGitRepo().then(o=>{i.update(0,o)})}function Me(){C&&C.dispose()}0&&(module.exports={activate,deactivate});
