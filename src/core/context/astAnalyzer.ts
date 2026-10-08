/**
 * Real Parser-Backed AST and Structural Syntax Analyzer
 * Uses official TypeScript compiler AST parser (ts.createSourceFile) when available
 * to inspect BinaryExpressions (env fallbacks), PropertyAssignments, ObjectLiterals,
 * and CallExpressions, with seamless multi-language lexical fallbacks.
 */

export interface AstAssignmentContext {
  variablePath?: string;
  isSensitiveProperty: boolean;
  isEnvFallback: boolean;
  isAuthorizationHeader: boolean;
  isLoggingCall: boolean;
  scopeType: 'VARIABLE_DECLARATION' | 'OBJECT_PROPERTY' | 'ENV_FALLBACK' | 'HEADER' | 'FUNCTION_ARG' | 'UNKNOWN';
}

const SENSITIVE_PROPERTY_REGEX = /(?:api_?key|secret|token|password|auth|credential|access_?key|private_?key)/i;
const LOGGING_REGEX = /(?:console\.(?:log|warn|error|info|debug)|logger\.|print\(|logging\.)/i;

// Dynamic import of TypeScript compiler API to avoid bundle bloat
let tsCompiler: any = null;
try {
  tsCompiler = require('typescript');
} catch {
  tsCompiler = null;
}

export function analyzeAstContext(
  contentLines: string[],
  targetLineZeroBased: number,
  filePath?: string
): AstAssignmentContext {
  const line = contentLines[targetLineZeroBased] || '';

  // 1. Try real TypeScript Compiler AST Parser if available and file is JS/TS
  if (tsCompiler) {
    const isJsTs = !filePath || /\.[jt]sx?$|\.m[jt]s$|\.c[jt]s$/i.test(filePath);
    if (isJsTs) {
      const astResult = analyzeWithTypeScriptCompiler(contentLines.join('\n'), targetLineZeroBased);
      if (astResult) {
        return astResult;
      }
    }
  }

  // 2. High-performance Lexical & Structural Fallback (for non-JS files or syntax disruptions)
  return analyzeLexicalAstFallback(line);
}

function analyzeWithTypeScriptCompiler(
  fullContent: string,
  targetLineZeroBased: number
): AstAssignmentContext | null {
  try {
    const ts = tsCompiler;
    const sourceFile = ts.createSourceFile(
      'eval_target.tsx',
      fullContent,
      ts.ScriptTarget.Latest,
      /* setParentNodes */ true,
      ts.ScriptKind.TSX
    );

    const lineStarts: number[] = sourceFile.getLineStarts();
    if (targetLineZeroBased >= lineStarts.length) return null;

    const lineStartPos = lineStarts[targetLineZeroBased];
    const lineEndPos =
      targetLineZeroBased + 1 < lineStarts.length
        ? lineStarts[targetLineZeroBased + 1] - 1
        : fullContent.length;

    let foundContext: AstAssignmentContext | null = null;

    function visit(node: any) {
      if (foundContext) return;
      if (node.pos > lineEndPos || node.end < lineStartPos) return;

      // Recurse to children first to discover the most specific inner AST construct
      ts.forEachChild(node, visit);
      if (foundContext) return;

      // Check 1: BinaryExpression fallback pattern (e.g. process.env.KEY || "hardcoded_secret")
      if (
        node.kind === ts.SyntaxKind.BinaryExpression &&
        (node.operatorToken.kind === ts.SyntaxKind.BarBarToken ||
          node.operatorToken.kind === ts.SyntaxKind.QuestionQuestionToken)
      ) {
        const leftText = node.left.getText(sourceFile);
        if (
          leftText.includes('process.env') ||
          leftText.includes('env') ||
          leftText.toLowerCase().includes('key')
        ) {
          foundContext = {
            variablePath: leftText,
            isSensitiveProperty: SENSITIVE_PROPERTY_REGEX.test(leftText),
            isEnvFallback: true,
            isAuthorizationHeader: false,
            isLoggingCall: false,
            scopeType: 'ENV_FALLBACK',
          };
          return;
        }
      }

      // Check 2: PropertyAssignment inside ObjectLiteral (e.g. { stripeKey: "sk_live_..." })
      if (node.kind === ts.SyntaxKind.PropertyAssignment) {
        const propName = node.name.getText(sourceFile);
        let parentPath = propName;

        // Traverse parent object hierarchy
        let curr = node.parent;
        while (curr) {
          if (curr.kind === ts.SyntaxKind.PropertyAssignment && curr.name) {
            parentPath = `${curr.name.getText(sourceFile)}.${parentPath}`;
          } else if (curr.kind === ts.SyntaxKind.VariableDeclaration && curr.name) {
            parentPath = `${curr.name.getText(sourceFile)}.${parentPath}`;
          }
          curr = curr.parent;
        }

        const isSensitive = SENSITIVE_PROPERTY_REGEX.test(parentPath);
        const isAuthHeader = /authorization|bearer|x-api-key/i.test(propName);

        foundContext = {
          variablePath: parentPath,
          isSensitiveProperty: isSensitive,
          isEnvFallback: false,
          isAuthorizationHeader: isAuthHeader,
          isLoggingCall: false,
          scopeType: isAuthHeader ? 'HEADER' : 'OBJECT_PROPERTY',
        };
        return;
      }

      // Check 3: CallExpression (e.g. logger.info("...") or connect("..."))
      if (node.kind === ts.SyntaxKind.CallExpression) {
        const exprText = node.expression.getText(sourceFile);
        const isLog = LOGGING_REGEX.test(exprText);
        if (isLog) {
          foundContext = {
            variablePath: exprText,
            isSensitiveProperty: false,
            isEnvFallback: false,
            isAuthorizationHeader: false,
            isLoggingCall: true,
            scopeType: 'FUNCTION_ARG',
          };
          return;
        }
      }

      // Check 4: VariableDeclaration (e.g. const apiKey = "...")
      if (node.kind === ts.SyntaxKind.VariableDeclaration) {
        const varName = node.name.getText(sourceFile);
        foundContext = {
          variablePath: varName,
          isSensitiveProperty: SENSITIVE_PROPERTY_REGEX.test(varName),
          isEnvFallback: false,
          isAuthorizationHeader: false,
          isLoggingCall: false,
          scopeType: 'VARIABLE_DECLARATION',
        };
        return;
      }
    }

    visit(sourceFile);
    return foundContext;
  } catch {
    return null;
  }
}

function analyzeLexicalAstFallback(line: string): AstAssignmentContext {
  const isLoggingCall = LOGGING_REGEX.test(line);
  const isEnvFallback = /(?:process\.env\.[A-Za-z0-9_]+|os\.(?:getenv|environ\.get)\([^)]+\))\s*(?:\|\||\?\?)\s*["'][^"']+["']/.test(
    line
  );
  const isAuthorizationHeader = /(?:authorization|x-api-key|bearer)\s*[:=]/i.test(line);

  const propMatch =
    line.match(/([a-zA-Z0-9_$.]+)\s*[:=]\s*["'][^"']+["']/) ||
    line.match(/["']([a-zA-Z0-9_.]+)["']\s*:\s*["'][^"']+["']/);

  let variablePath: string | undefined;
  let isSensitiveProperty = false;

  if (propMatch) {
    variablePath = propMatch[1];
    isSensitiveProperty = SENSITIVE_PROPERTY_REGEX.test(variablePath);
  }

  let scopeType: AstAssignmentContext['scopeType'] = 'UNKNOWN';
  if (isEnvFallback) {
    scopeType = 'ENV_FALLBACK';
  } else if (isAuthorizationHeader) {
    scopeType = 'HEADER';
  } else if (variablePath && variablePath.includes('.')) {
    scopeType = 'OBJECT_PROPERTY';
  } else if (variablePath) {
    scopeType = 'VARIABLE_DECLARATION';
  } else if (isLoggingCall) {
    scopeType = 'FUNCTION_ARG';
  }

  return {
    variablePath,
    isSensitiveProperty,
    isEnvFallback,
    isAuthorizationHeader,
    isLoggingCall,
    scopeType,
  };
}
