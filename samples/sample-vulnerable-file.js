// Sample Vulnerable File for Testing Secret Leak Detector
// As soon as this file is opened or saved in VS Code, the extension will underline the secrets!

const AWS_ACCESS_KEY_ID = "AKIA1234567890ABCDEF";
const GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz";
const STRIPE_SECRET_KEY = "sk_test_51Abcdefghijklmnopqrstuvwx";
const OPENAI_API_KEY = "sk-proj-1234567890abcdefghijklmnopqrstuvwxyz1234567890abcdef";
const DATABASE_URL = "postgres://admin:SuperSecretPass123!@db.internal.company.com:5432/prod_db";

function connect() {
  console.log("Connecting using credentials...");
}
