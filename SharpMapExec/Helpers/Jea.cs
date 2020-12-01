using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation.Language;
using System.Text.RegularExpressions;

namespace SharpMapExec.Helpers
{
    public static class Extension
    {
        public static bool In(this string source, string toCheck, StringComparison comp)
        {
            return source?.IndexOf(toCheck, comp) >= 0;
        }

        public static bool In<T>(this T item, bool regex, List<string> items)
        {
            if (items == null)
                throw new ArgumentNullException("items");

            if (regex)
            {
                string pattern = Regex.Escape(item.ToString()).Replace(@"\*", ".*").Replace(@"\?", ".");
                return items.Any(testitem => Regex.IsMatch(testitem.ToString(), pattern));
            }
            else
            {
                return items.Contains(item.ToString().ToLower());
            }
        }
    }

    public class Jea
    {
        //https://github.com/mkropat/PowershellAstWriter/blob/48140116ee3cd6ab9f20725c669c6c0fb8e7ce9d/PowershellAstWriterTests/PowershellAstWriterTests.cs

        public static void RunAllChecks(string scriptblock)
        {
            MeasureInvokeExpression(scriptblock);
            //MeasureAddType(scriptblock);
            MeasureDangerousMethod(scriptblock);
            MeasureCommandInjection(scriptblock);
            MeasureForeachObjectInjection(scriptblock);
            MeasurePropertyInjection(scriptblock);
            MeasureMethodInjection(scriptblock);
            MeasureUnsafeEscaping(scriptblock);
        }

        public static void MeasureInvokeExpression(string ScriptBlock)
        {
            Token[] token;
            ParseError[] error;
            ScriptBlockAst ScriptBlockAst = Parser.ParseInput(ScriptBlock, out token, out error);

            Func<Ast, bool> predicate = delegate (Ast ast)
            {
                var derpVar = new VariableExpressionAst(ast.Extent, "Derp", splatted: false);
                CommandAst targetAst = new CommandAst(ast.Extent, new[] { derpVar }, TokenKind.Unknown, Enumerable.Empty<RedirectionAst>());
                if (targetAst != null)
                {
                    if (targetAst.CommandElements[0].Extent.Text.In(false, new List<string> { "iex", "invoke-expression" }))
                    {
                        return true;
                    }
                }
                return false;
            };

            var foundNode = ScriptBlockAst.Find(predicate, true);
            if (foundNode != null)
            {
                Console.WriteLine("[+] Possible injection vulnerability found");
                Console.WriteLine(String.Format(@"Possible script injection risk via the Invoke-Expression cmdlet. Untrusted input can cause arbitrary PowerShell expressions to be run.
Variables may be used directly for dynamic parameter arguments, splatting can be used for dynamic parameter names, and the invocation operator can be used for dynamic command names.
If content escaping is truly needed, PowerShell has several valid quote characters, so  [System.Management.Automation.Language.CodeGeneration]::Escape* should be used.
RuleName = InjectionRisk.InvokeExpression
Severity = Warning", foundNode.Extent
                ));
            }
        }

        //public static void MeasureAddType(string ScriptBlock)
        //{
        //    Token[] token;
        //    ParseError[] error;
        //    ScriptBlockAst ScriptBlockAst = Parser.ParseInput(ScriptBlock, out token, out error);
        //
        //    Func<Ast, bool> predicate = delegate (Ast ast)
        //    {
        //        var derpVar = new VariableExpressionAst(ast.Extent, "Derp", splatted: false);
        //        CommandAst targetAst = new CommandAst(ast.Extent, new[] { derpVar }, TokenKind.Unknown, Enumerable.Empty<RedirectionAst>());
        //        if (targetAst.CommandElements[0].Extent.Text == "Add-Type")
        //        {
        //            var addTypeParameters = StaticParameterBinder.BindCommand(targetAst);
        //            var typeDefinitionParameter = addTypeParameters.BoundParameters.TypeDefinition;
        //            if (typeDefinitionParameter.ConstantValue)
        //            {
        //                if (addTypeParameters.BoundParameters.TypeDefinition.ValueSystem.Management.Automation.Language.VariableExpressionAst)
        //                {
        //                    var variableName = addTypeParameters.BoundParameters.TypeDefinition.Value.VariablePath.UserPath;
        //                    var constantAssignmentForVariable = ScriptBlockAst.FindAll(tempvar => tempvar is Ast, true);
        //                    if (assignmentAst && assignmentAst.Left.VariablePath.UserPath == variableName && assignmentAst.Right.ExpressionSystem.Management.Automation.Language.ConstantExpressionAst)
        //                    {
        //                        return true;
        //                    }
        //                    if (constantAssignmentForVariable != null)
        //                    {
        //                        return false;
        //                    }
        //                    else
        //                    {
        //                        return true;
        //                    }
        //                }
        //                return true;
        //            }
        //        }
        //        return false;
        //    };
        //
        //    var foundNode = ScriptBlockAst.Find(predicate, true);
        //    if (foundNode != null)
        //    {
        //        Console.WriteLine("[+] Possible injection vulnerability found");
        //        Console.WriteLine(String.Format(@"Possible code injection risk via the Add-Type cmdlet. Untrusted input can cause arbitrary Win32 code to be run..
//RuleName = InjectionRisk.AddType
//Severity = Warning", foundNode.Extent
        //        ));
        //    }
        //}

        public static void MeasureDangerousMethod(string ScriptBlock)
        {
            Token[] token;
            ParseError[] error;
            ScriptBlockAst ScriptBlockAst = Parser.ParseInput(ScriptBlock, out token, out error);

            Func<Ast, bool> predicate = delegate (Ast ast)
            {
                var derpVar = new VariableExpressionAst(ast.Extent, "Derp", splatted: false);
                var derpVar2 = new StringConstantExpressionAst(ast.Extent, "derbvar2", StringConstantType.BareWord);
                InvokeMemberExpressionAst targetAst = new InvokeMemberExpressionAst(ast.Extent, derpVar, derpVar2, Enumerable.Empty<ExpressionAst>(), false);
                if (targetAst != null)
                {
                    if (targetAst.Member.Extent.Text.In(false, new List<string> { "invokescript", "createnestedpipeline", "addscript", "newscriptblock", "expandstring" }))
                    {
                        return true;
                    }
                    if (targetAst.Member.Extent.Text.In(false, new List<string> { "create" }) && targetAst.Expression.Extent.Text.In(false, new List<string> { "scriptblock" }))
                    {
                        return true;
                    }
                }
                return false;
            };

            var foundNode = ScriptBlockAst.Find(predicate, true);
            if (foundNode != null)
            {
                Console.WriteLine("[+] Possible injection vulnerability found");
                Console.WriteLine(String.Format(@"Possible script injection risk via the a dangerous method. Untrusted input can cause arbitrary PowerShell expressions to be run.
The PowerShell.AddCommand().AddParameter() APIs should be used instead.
RuleName = {1}
Severity = Warning", foundNode.Extent, foundNode.Extent.Text)
                );
            }
        }

        public static void MeasureCommandInjection(string ScriptBlock)
        {
            Token[] token;
            ParseError[] error;
            ScriptBlockAst ScriptBlockAst = Parser.ParseInput(ScriptBlock, out token, out error);

            Func<Ast, bool> predicate = delegate (Ast ast)
            {
                var derpVar = new VariableExpressionAst(ast.Extent, "Derp", splatted: false);
                CommandAst targetAst = new CommandAst(ast.Extent, new[] { derpVar }, TokenKind.Unknown, Enumerable.Empty<RedirectionAst>());
                if (targetAst != null)
                {
                    if (targetAst.CommandElements[0].Extent.Text.In(false, new List<string> { "cmd", "powershell" }))
                    {
                        var commandInvoked = targetAst.CommandElements[1];
                        for (int parameterPosition = 1; parameterPosition < targetAst.CommandElements.Count; parameterPosition++)
                        {
                            if (targetAst.CommandElements[parameterPosition].Extent.Text.In(false, new List<string> { "/c", "/k", "command", "-c", "-enc" }))
                            {
                                commandInvoked = targetAst.CommandElements[parameterPosition + 1];
                                break;
                            }
                        }
                        if (commandInvoked is ExpandableStringExpressionAst)
                        {
                            return true;
                        }
                    }
                }
                return false;
            };

            var foundNode = ScriptBlockAst.Find(predicate, true);
            if (foundNode != null)
            {
                Console.WriteLine("[+] Possible injection vulnerability found");
                Console.WriteLine(String.Format(@"Possible command injection risk via calling cmd.exe or powershell.exe. Untrusted input can cause arbitrary commands to be run.
Input should be provided as variable input directly (such as 'cmd /c ping $destination', rather than within an expandable string.
The PowerShell.AddCommand().AddParameter() APIs should be used instead.
RuleName = InjectionRisk.CommandInjection
Severity = Warning", foundNode.Extent));
            }
        }

        public static void MeasureForeachObjectInjection(string ScriptBlock)
        {
            Token[] token;
            ParseError[] error;
            ScriptBlockAst ScriptBlockAst = Parser.ParseInput(ScriptBlock, out token, out error);

            Func<Ast, bool> predicate = delegate (Ast ast)
            {
                var derpVar = new VariableExpressionAst(ast.Extent, "Derp", splatted: false);
                CommandAst targetAst = new CommandAst(ast.Extent, new[] { derpVar }, TokenKind.Unknown, Enumerable.Empty<RedirectionAst>());
                if (targetAst != null)
                {
                    if (targetAst.CommandElements[0].Extent.Text.In(false, new List<string> { "foreach", "%" }))
                    {
                        var memberInvoked = targetAst.CommandElements[1];
                        for (int parameterPosition = 1; parameterPosition < targetAst.CommandElements.Count; parameterPosition++)
                        {
                            if (targetAst.CommandElements[parameterPosition].Extent.Text.In(false, new List<string> { "process", "membername" }))
                            {
                                memberInvoked = targetAst.CommandElements[parameterPosition + 1];
                                break;
                            }
                        }
                        if (memberInvoked is ConstantExpressionAst && memberInvoked is ScriptBlockExpressionAst)
                        {
                            return true;
                        }
                    }
                }
                return false;
            };
            var foundNode = ScriptBlockAst.Find(predicate, true);
            if (foundNode != null)
            {
                Console.WriteLine("[+] Possible injection vulnerability found");
                Console.WriteLine(String.Format(@"Possible property access injection via Foreach-Object. Untrusted input can cause arbitrary properties /methods to be accessed:
RuleName = InjectionRisk.ForeachObjectInjection
Severity = Warning", foundNode.Extent));
            }
        }

        public static void MeasurePropertyInjection(string ScriptBlock)
        {
            Token[] token;
            ParseError[] error;
            ScriptBlockAst ScriptBlockAst = Parser.ParseInput(ScriptBlock, out token, out error);

            Func<Ast, bool> predicate = delegate (Ast ast)
            {
                var derpVar = new VariableExpressionAst(ast.Extent, "Derp", splatted: false);
                var derpVar2 = new StringConstantExpressionAst(ast.Extent, "Derpvr2", StringConstantType.BareWord);
                InvokeMemberExpressionAst methodAst = new InvokeMemberExpressionAst(ast.Extent, derpVar, derpVar2, Enumerable.Empty<ExpressionAst>(), @static: false);
                var ast2 = ast.Copy();
                var derpVar3 = new VariableExpressionAst(ast2.Extent, "Derp3", splatted: false);
                var derpVar4 = new StringConstantExpressionAst(ast2.Extent, "Derpvr4", StringConstantType.BareWord);
                MemberExpressionAst targetAst = new MemberExpressionAst(ast2.Extent, derpVar3, derpVar4, @static: false);
                if (targetAst != null && methodAst == null)
                {
                    if (!(targetAst.Member is ConstantExpressionAst))
                    {
                        return true;
                    }
                }
                return false;
            };

            var foundNode = ScriptBlockAst.Find(predicate, true);
            if (foundNode != null)
            {
                Console.WriteLine("[+] Possible injection vulnerability found");
                Console.WriteLine(String.Format(@"Possible property access injection via dynamic member access. Untrusted input can cause arbitrary static properties to be accessed:
RuleName = InjectionRisk.StaticPropertyInjection
Severity = Warning", foundNode.Extent));
            }
        }

        public static void MeasureMethodInjection(string ScriptBlock)
        {
            Token[] token;
            ParseError[] error;
            ScriptBlockAst ScriptBlockAst = Parser.ParseInput(ScriptBlock, out token, out error);

            Func<Ast, bool> predicate = delegate (Ast ast)
            {
                var derpVar = new VariableExpressionAst(ast.Extent, "Derp", splatted: false);
                var derpVar2 = new StringConstantExpressionAst(ast.Extent, "Derpvr2", StringConstantType.BareWord);
                InvokeMemberExpressionAst targetAst = new InvokeMemberExpressionAst(ast.Extent, derpVar, derpVar2, Enumerable.Empty<ExpressionAst>(), @static: false);
                if (targetAst != null)
                {
                    if (targetAst.Member is ConstantExpressionAst)
                    {
                        return true;
                    }
                }
                return false;
            };

            var foundNode = ScriptBlockAst.Find(predicate, true);
            if (foundNode != null)
            {
                Console.WriteLine("[+] Possible injection vulnerability found");
                Console.WriteLine(String.Format(@"Possible property access injection via dynamic member access. Untrusted input can cause arbitrary static properties to be accessed:
RuleName = InjectionRisk.MethodInjection
Severity = Warning", foundNode.Extent));
            }
        }

        public static void MeasureUnsafeEscaping(string ScriptBlock)
        {
            Token[] token;
            ParseError[] error;
            ScriptBlockAst ScriptBlockAst = Parser.ParseInput(ScriptBlock, out token, out error);

            Func<Ast, bool> predicate = delegate (Ast ast)
            {
                var leftVariable = new VariableExpressionAst(ast.Extent, "herp", splatted: false);
                var rightVariable = new VariableExpressionAst(ast.Extent, "derp", splatted: false);
                var targetAst = new BinaryExpressionAst(ast.Extent, leftVariable, TokenKind.Ieq, rightVariable, ast.Extent);
                if (targetAst != null)
                {
                    if (targetAst.Operator.In(false, new List<string> { "replace" }) && targetAst.Right.Extent.Text.In(false, new List<string> { "`", "'" }))
                    {
                        return true;
                    }
                }
                return false;
            };

            var foundNode = ScriptBlockAst.Find(predicate, true);
            if (foundNode != null)
            {
                Console.WriteLine("[+] Possible injection vulnerability found");
                Console.WriteLine(@"Possible unsafe use of input escaping. Variables may be used directly for dynamic parameter arguments, splatting can be used for dynamic parameter names,
and the invocation operator can be used for dynamic command names. If content escaping is truly needed, PowerShell has several valid quote characters,
so the  [System.Management.Automation.Language.CodeGeneration]::Escape* should be used instead
RuleName = InjectionRisk.UnsafeEscaping
Severity = Warning");
            }
        }
    }
}