using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Text;
using System.Linq;
using static System.Console;
using System.Xml.Linq;
using SoftEther.JsonRpc;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json.Serialization;
using Markdig;

namespace VPNServer_JSONRPC_CodeGen
{
    public enum TargetLang
    {
        CSharp,
        TypeScript,
    }

    static class CodeGenUtil
    {
        public static string AppExeDir;
        public static string ProjectDir;
        public static string VpnSrcDir;
        public static string OutputDir_Clients;
        public static string OutputDir_HamCore;

        static CodeGenUtil()
        {
            AppExeDir = System.AppContext.BaseDirectory;
            ProjectDir = AppExeDir;
            string tmp = AppExeDir;
            while (true)
            {
                try
                {
                    tmp = Path.GetDirectoryName(tmp);
                    if (Directory.GetFiles(tmp, "*.csproj").Length >= 1)
                    {
                        ProjectDir = tmp;
                        break;
                    }
                }
                catch
                {
                    break;
                }
            }
            OutputDir_Clients = Path.Combine(ProjectDir, @"..\vpnserver-jsonrpc-clients");

            string root_dir = Path.Combine(ProjectDir, @"..\..");
            string dirname = null;
            if (Directory.Exists(Path.Combine(root_dir, "Main"))) dirname = "Main";
            if (Directory.Exists(Path.Combine(root_dir, "src"))) dirname = "src";
            if (string.IsNullOrEmpty(dirname)) throw new ApplicationException($"Directory '{root_dir}' is not a root dir.");

            VpnSrcDir = dirname;

            OutputDir_HamCore = Path.Combine(root_dir, dirname, @"bin\hamcore");
            if (Directory.Exists(OutputDir_HamCore) == false) throw new ApplicationException($"Direction '{OutputDir_HamCore}' not found.");
        }

        public static void MakeDir(string path)
        {
            try
            {
                Directory.CreateDirectory(path);
            }
            catch
            {
            }
        }
    }

    class CSharpSourceCode
    {
        public SyntaxTree Tree { get; }
        public CompilationUnitSyntax Root { get; }
        public SemanticModel Model { get; set; }

        public CSharpSourceCode(string filename) : this(File.ReadAllText(filename), filename)
        {
        }

        public CSharpSourceCode(string body, string filename)
        {
            this.Tree = CSharpSyntaxTree.ParseText(body, path: filename);
            this.Root = this.Tree.GetCompilationUnitRoot();
        }
    }


    class CSharpCompiler
    {
        public string AssemblyName { get; }
        public List<MetadataReference> ReferencesList { get; } = new List<MetadataReference>();
        public List<CSharpSourceCode> SourceCodeList { get; } = new List<CSharpSourceCode>();

        CSharpCompilation _compilation = null;

        public CSharpCompilation Compilation
        {
            get
            {
                if (_compilation == null)
                {
                    _compilation = CSharpCompilation.Create(this.AssemblyName,
                        this.SourceCodeList.Select(s => s.Tree),
                        this.ReferencesList,
                        options: new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary, optimizationLevel: OptimizationLevel.Debug,
                        assemblyIdentityComparer: DesktopAssemblyIdentityComparer.Default));

                }
                return _compilation;
            }
        }

        public CSharpCompiler(string assembly_name)
        {
            this.AssemblyName = assembly_name;
        }

        public void AddReference(MetadataReference r)
        {
            this.ReferencesList.Add(r);
        }
        public void AddReferenceByPath(string path)
        {
            AddReference(MetadataReference.CreateFromFile(path));
        }
        public void AddReferenceByType(Type type)
        {
            AddReferenceByPath(type.Assembly.Location);
        }
        public void AddReferenceByAssemblyName(string name)
        {
            var a = System.Reflection.Assembly.Load(new System.Reflection.AssemblyName(name));

            AddReferenceByPath(a.Location);
        }
        public void AddReferenceDotNetStandard()
        {
            var a = System.Reflection.Assembly.Load(new System.Reflection.AssemblyName("netstandard"));

            AddReferenceByPath(a.Location);

            string dir = Path.GetDirectoryName(a.Location);

            AddReferenceByPath(Path.Combine(dir, "System.Private.CoreLib.dll"));
            
            foreach (var refa in a.GetReferencedAssemblies())
            {
                string dll_name = Path.Combine(dir, refa.Name) + ".dll";

                if (File.Exists(dll_name))
                {
                    AddReferenceByPath(dll_name);
                }
            }
        }

        public void AddSourceCode(CSharpSourceCode cs)
        {
            this.SourceCodeList.Add(cs);
        }

        public bool OkOrPrintErrors()
        {
            MemoryStream ms = new MemoryStream();
            Microsoft.CodeAnalysis.Emit.EmitResult ret = Compilation.Emit(ms);

            if (ret.Success)
            {
                return true;
            }

            IEnumerable<Diagnostic> failures = ret.Diagnostics.Where(diagnostic =>
                        diagnostic.IsWarningAsError ||
                        diagnostic.Severity == DiagnosticSeverity.Error);

            foreach (Diagnostic diagnostic in failures)
            {
                WriteLine(diagnostic.ToString());
            }
            return false;
        }

        public void Compile(bool test_full_compile = false)
        {
            if (test_full_compile)
            {
                if (OkOrPrintErrors() == false)
                {
                    throw new ApplicationException("Compile Error.");
                }
            }

            foreach (CSharpSourceCode cs in this.SourceCodeList)
            {
                cs.Model = this.Compilation.GetSemanticModel(cs.Tree);
            }
        }
    }

    class GeneratedCodePart
    {
        public int Seq = 0;
        public string Text = "";
    }

    class GeneratedCodeSection
    {
        public List<GeneratedCodePart> PartList = new List<GeneratedCodePart>();

        public override string ToString()
        {
            StringWriter w = new StringWriter();
            var a = this.PartList.OrderBy(x => x.Seq);

            foreach (var b in a)
            {
                w.Write(b.Text.ToString());
            }

            return w.ToString();
        }

        public void AddPart(int seq, string text)
        {
            this.PartList.Add(new GeneratedCodePart() { Seq = seq, Text = text });
        }
    }

    class GeneratedCode
    {
        public GeneratedCodeSection Types = new GeneratedCodeSection();
        public GeneratedCodeSection Stubs = new GeneratedCodeSection();
        public GeneratedCodeSection Tests = new GeneratedCodeSection();

        public override string ToString()
        {
            StringWriter w = new StringWriter();

            w.WriteLine("// --- Types ---");
            w.Write(this.Types.ToString());
            w.WriteLine();

            w.WriteLine("// --- Stubs ---");
            w.Write(this.Stubs.ToString());
            w.WriteLine();

            w.WriteLine("// --- Tests ---");
            w.Write(this.Tests.ToString());
            w.WriteLine();

            return w.ToString();
        }
    }

    class GeneratedCodeForLang
    {
        public GeneratedCode TypeScript = new GeneratedCode();

        public string DocsRpc = "";
    }

    static class CodeGenExtensions
    {
        public static string GetDocumentStr(this ISymbol sym)
        {
            if (sym == null) return "";
            string xml = sym.GetDocumentationCommentXml();
            if (string.IsNullOrEmpty(xml)) return "";
            XDocument doc = XDocument.Parse(xml);
            var summary = doc.Descendants("summary").FirstOrDefault();
            string str = summary.Value;
            if (string.IsNullOrEmpty(str)) return "";
            str = str.Replace(" (Async mode)", "", StringComparison.InvariantCultureIgnoreCase);
            str = str.Trim();
            return str;
        }
    }

    class RpcInfo
    {
        public string Name;
        public string TypeName;

        public IMethodSymbol Symbol;

        public HashSet<string> InputParamMembers = new HashSet<string>();
    }

    class RpcTypeParameterInfo
    {
        public string Name;
        public string Type;
        public string Description;
    }

    class RpcTypeInfo
    {
        public string Name;
        public string Description;

        public List<RpcTypeParameterInfo> Params = new List<RpcTypeParameterInfo>();
        public List<string> SubTypes = new List<string>();
    }

    class CodeGen
    {
        CSharpSourceCode cs_types, cs_stubs, cs_tests;

        public Dictionary<string, RpcInfo> rpc_list = new Dictionary<string, RpcInfo>();
        public Dictionary<string, RpcTypeInfo> rpc_type_list = new Dictionary<string, RpcTypeInfo>();

        CSharpCompiler csc;

        public CodeGen()
        {
            csc = new CSharpCompiler("Test");

            csc.AddReferenceDotNetStandard();
            csc.AddReferenceByType(typeof(Newtonsoft.Json.JsonPropertyAttribute));

            cs_types = new CSharpSourceCode(Path.Combine(CodeGenUtil.ProjectDir, @"VpnServerRpc\VPNServerRpcTypes.cs"));
            csc.AddSourceCode(cs_types);

            cs_stubs = new CSharpSourceCode(Path.Combine(CodeGenUtil.ProjectDir, @"VpnServerRpc\VPNServerRpc.cs"));
            csc.AddSourceCode(cs_stubs);

            cs_tests = new CSharpSourceCode(Path.Combine(CodeGenUtil.ProjectDir, @"VpnServerRpcTest\VpnServerRpcTest.cs"));
            csc.AddSourceCode(cs_tests);

            csc.Compile();
        }

        void generate_types(GeneratedCodeForLang ret)
        {
            var model = cs_types.Model;

            var class_list = cs_types.Root.DescendantNodes().OfType<ClassDeclarationSyntax>();

            foreach (ClassDeclarationSyntax c in class_list)
            {
                StringWriter ts = new StringWriter();

                string doc = model.GetDeclaredSymbol(c).GetDocumentStr();
                if (string.IsNullOrEmpty(doc) == false)
                {
                    ts.WriteLine($"/** {doc} */");
                }

                RpcTypeInfo info = new RpcTypeInfo()
                {
                    Name = c.Identifier.Text,
                    Description = doc,
                };
                rpc_type_list[c.Identifier.Text] = info;

                ts.WriteLine($"export class {c.Identifier.Text}");
                ts.WriteLine("{");

                foreach (var member in model.GetDeclaredSymbol(c).GetMembers())
                {
                    string json_name = "";
                    bool json_name_has_special_char = false;
                    var atts = member.GetAttributes();
                    var y = atts.Where(x => x.AttributeClass.Name == "JsonPropertyAttribute").FirstOrDefault();
                    if (y != null)
                    {
                        json_name = y.ConstructorArguments.FirstOrDefault().Value.ToString();
                        if (json_name.IndexOf(':') != -1 || json_name.IndexOf('.') != -1) json_name_has_special_char = true;
                    }

                    string default_value = "\"\"";

                    string enum_type = "";

                    switch (member)
                    {
                        case IFieldSymbol field:
                            string ts_type = "";
                            ITypeSymbol type = field.Type;
                            switch (type.Kind)
                            {
                                case SymbolKind.NamedType:
                                    switch (type.Name)
                                    {
                                        case "UInt32":
                                        case "UInt64":
                                            ts_type = "number";
                                            default_value = "0";
                                            break;

                                        case "String":
                                            ts_type = "string";
                                            break;

                                        case "Boolean":
                                            ts_type = "boolean";
                                            default_value = "false";
                                            break;

                                        case "DateTime":
                                            ts_type = "Date";
                                            default_value = "new Date()";
                                            break;

                                        default:
                                            if (type.TypeKind == TypeKind.Enum)
                                            {
                                                ts_type = type.Name;
                                                enum_type = type.Name;
                                                default_value = "0";
                                                break;
                                            }
                                            throw new ApplicationException($"{c.Identifier}.{member.Name}: type.Name = {type.Name}");
                                    }
                                    break;

                                case SymbolKind.ArrayType:
                                    ITypeSymbol type2 = ((IArrayTypeSymbol)type).ElementType;

                                    default_value = "[]";

                                    switch (type2.Kind)
                                    {
                                        case SymbolKind.NamedType:
                                            switch (type2.Name)
                                            {
                                                case "UInt32":
                                                case "UInt64":
                                                    ts_type = "number[]";
                                                    break;

                                                case "String":
                                                    ts_type = "string[]";
                                                    break;

                                                case "Boolean":
                                                    ts_type = "boolean[]";
                                                    break;

                                                case "Byte":
                                                    ts_type = "Uint8Array";
                                                    default_value = "new Uint8Array([])";
                                                    break;

                                                default:
                                                    if (type2.ContainingAssembly.Name == csc.AssemblyName)
                                                    {
                                                        ts_type = type2.Name + "[]";
                                                        enum_type = type2.Name;
                                                        break;
                                                    }
                                                    throw new ApplicationException($"{c.Identifier}.{member.Name}: type2.Name = {type2.Name}");
                                            }
                                            break;

                                        default:
                                            throw new ApplicationException($"{c.Identifier}.{member.Name}: type2.Kind = {type2.Kind}");
                                    }

                                    break;

                                default:
                                    throw new ApplicationException($"{c.Identifier}.{member.Name}: type.Kind = {type.Kind}");
                            }

                            if (string.IsNullOrEmpty(ts_type) == false)
                            {
                                string field_name = field.Name;
                                string doc2 = member.GetDocumentStr();

                                if (string.IsNullOrEmpty(json_name) == false) field_name = json_name;

                                string info_type = ts_type;
                                string info_type2 = "";
                                if (field_name.EndsWith("_str")) info_type2 = "ASCII";
                                if (field_name.EndsWith("_utf")) info_type2 = "UTF8";
                                if (field_name.EndsWith("_ip")) info_type2 = "IP address";
                                if (field_name.EndsWith("_u32")) info_type2 = "uint32";
                                if (field_name.EndsWith("_u64")) info_type2 = "uint64";
                                if (field_name.EndsWith("_bin")) { info_type2 = "Base64 binary"; info_type = "string"; }

                                string docs_add = "";

                                if (string.IsNullOrEmpty(enum_type) == false)
                                {
                                    Type et = Type.GetType("SoftEther.VPNServerRpc." + enum_type);
                                    if (et.IsEnum)
                                    {
                                        docs_add += "<BR>Values:";

                                        var ed = cs_types.Root.DescendantNodes().OfType<EnumDeclarationSyntax>()
                                            .Where(e => e.Identifier.Text == enum_type)
                                            .Single();

                                        foreach (var em in model.GetDeclaredSymbol(ed).GetMembers())
                                        {
                                            switch (em)
                                            {
                                                case IFieldSymbol ef:
                                                    if (ef.IsConst && ef.IsDefinition)
                                                    {
                                                        string doc3 = em.GetDocumentStr();
                                                        docs_add += $"<BR>`{ef.ConstantValue}`: {doc3}";
                                                    }
                                                    break;
                                            }
                                        }

                                        info_type = "number";
                                        info_type2 = "enum";
                                    }
                                    else
                                    {
                                        if (info.SubTypes.Contains(enum_type) == false)
                                        {
                                            info.SubTypes.Add(enum_type);
                                            info_type = "Array object";
                                        }
                                    }
                                }

                                info_type = "`" + info_type + "`";
                                if (string.IsNullOrEmpty(info_type2) == false) info_type += " (" + info_type2 + ")";

                                info.Params.Add(new RpcTypeParameterInfo()
                                {
                                    Name = field_name,
                                    Type = info_type,
                                    Description = doc2 + docs_add,
                                });

                                if (json_name_has_special_char) field_name = $"[\"{json_name}\"]";

                                if (string.IsNullOrEmpty(doc2) == false)
                                {
                                    ts.WriteLine($"    /** {doc2} */");
                                }

                                ts.WriteLine($"    public {field_name}: {ts_type} = {default_value};");

                                ts.WriteLine();
                            }
                            break;

                        case IMethodSymbol method when method.MethodKind == MethodKind.Constructor:
                            break;

                        default:
                            throw new ApplicationException($"{c.Identifier}.{member.Name}: type = {member.GetType()}");
                    }
                }

                if (string.IsNullOrEmpty(doc) == false)
                {
                    ts.WriteLine($"    /** Constructor for the '{c.Identifier.Text}' class: {doc} */");
                }
                ts.WriteLine($"    public constructor(init?: Partial<{c.Identifier.Text}>)");
                ts.WriteLine("    {");
                ts.WriteLine("        Object.assign(this, init);");
                ts.WriteLine("    }");

                ts.WriteLine("}");
                ts.WriteLine();

                ret.TypeScript.Types.AddPart(c.SpanStart, ts.ToString());
            }

            var enum_list = cs_types.Root.DescendantNodes().OfType<EnumDeclarationSyntax>();

            foreach (EnumDeclarationSyntax e in enum_list)
            {
                StringWriter ts = new StringWriter();

                string doc = model.GetDeclaredSymbol(e).GetDocumentStr();
                if (string.IsNullOrEmpty(doc) == false)
                {
                    ts.WriteLine($"/** {doc} */");
                }

                ts.WriteLine($"export enum {e.Identifier.Text}");
                ts.WriteLine("{");

                foreach (var member in model.GetDeclaredSymbol(e).GetMembers())
                {
                    switch (member)
                    {
                        case IFieldSymbol field:
                            if (field.IsConst && field.IsDefinition)
                            {
                                string doc2 = member.GetDocumentStr();
                                if (string.IsNullOrEmpty(doc2) == false)
                                {
                                    ts.WriteLine($"    /** {doc2} */");
                                }

                                ts.WriteLine($"    {field.Name} = {field.ConstantValue},");

                                ts.WriteLine();
                            }
                            break;
                    }
                }

                ts.WriteLine("}");
                ts.WriteLine();

                ret.TypeScript.Types.AddPart(e.SpanStart, ts.ToString());
            }
        }

        void generate_stubs(GeneratedCodeForLang ret)
        {
            var model = cs_stubs.Model;

            var rpc_class = cs_stubs.Root.DescendantNodes().OfType<ClassDeclarationSyntax>().Where(c => c.Identifier.Text == "VpnServerRpc").First();

            var members = model.GetDeclaredSymbol(rpc_class).GetMembers();

            var methods = members.Where(m => m is IMethodSymbol).Select(m => m as IMethodSymbol).Where(m => m.IsStatic == false)
                .Where(m => m.IsAsync).Where(m => m.Name != "CallAsync");

            foreach (var method in methods)
            {
                string method_name = method.Name;
                if (method_name.EndsWith("Async") == false) throw new ApplicationException($"{method.Name}: method_name = {method_name}");
                method_name = method_name.Substring(0, method_name.Length - 5);

                INamedTypeSymbol ret_type = (INamedTypeSymbol)method.ReturnType;
                if (ret_type.Name != "Task") throw new ApplicationException($"{method.Name}: ret_type.Name = {ret_type.Name}");

                var ret_type_args = ret_type.TypeArguments;
                if (ret_type_args.Length != 1) throw new ApplicationException($"{method.Name}: type_args.Length = {ret_type_args.Length}");

                var ret_type_name = ret_type_args[0].Name;

                if (method.Parameters.Length >= 2) throw new ApplicationException($"{method.Name}: method.Parameters.Length = {method.Parameters.Length}");

                if (method.DeclaringSyntaxReferences.Length != 1) throw new ApplicationException($"{method.Name}: method.DeclaringSyntaxReferences.Length = {method.DeclaringSyntaxReferences.Length}");

                MethodDeclarationSyntax syntax = (MethodDeclarationSyntax)method.DeclaringSyntaxReferences[0].GetSyntax();
                if (syntax.Body != null) throw new ApplicationException($"{method.Name}: syntax.Body != null");
                if (syntax.ExpressionBody == null) throw new ApplicationException($"{method.Name}: syntax.ExpressionBody == null");

                ArrowExpressionClauseSyntax body = syntax.ExpressionBody;
                InvocationExpressionSyntax invoke = body.DescendantNodes().OfType<InvocationExpressionSyntax>().Single();

                if (model.GetSymbolInfo(invoke.Expression).Symbol.Name != "CallAsync") throw new ApplicationException($"{method.Name}: model.GetSymbolInfo(invoke.Expression).Symbol.Name = {model.GetSymbolInfo(invoke.Expression).Symbol.Name}");

                if (invoke.ArgumentList.Arguments.Count != 2) throw new ApplicationException($"{method.Name}: invoke.ArgumentList.Arguments.Count = {invoke.ArgumentList.Arguments.Count}");

                LiteralExpressionSyntax str_syntax = (LiteralExpressionSyntax)invoke.ArgumentList.Arguments[0].Expression;

                string str = str_syntax.Token.Text;

                StringWriter ts = new StringWriter();

                string doc2 = method.GetDocumentStr();
                if (string.IsNullOrEmpty(doc2) == false)
                {
                    ts.WriteLine($"    /** {doc2} */");
                }

                if (method.Parameters.Length == 0)
                {
                    ts.WriteLine($"    public {method_name} = (): Promise<{ret_type_name}> =>");
                    ts.WriteLine("    {");
                    ts.WriteLine($"        return this.CallAsync<{ret_type_name}>({str}, new {ret_type_name}());");
                    ts.WriteLine("    }");
                    ts.WriteLine("    ");
                }
                else
                {
                    ts.WriteLine($"    public {method_name} = (in_param: {ret_type_name}): Promise<{ret_type_name}> =>");
                    ts.WriteLine("    {");
                    ts.WriteLine($"        return this.CallAsync<{ret_type_name}>({str}, in_param);");
                    ts.WriteLine("    }");
                    ts.WriteLine("    ");
                }

                rpc_list[method_name] = new RpcInfo()
                {
                    Name = method_name,
                    TypeName = ret_type_name,
                    Symbol = method,
                };

                ret.TypeScript.Stubs.AddPart(method.DeclaringSyntaxReferences[0].Span.Start, ts.ToString());
            }
        }

        class CcWalker :  CSharpSyntaxWalker
        {
            StringWriter w = new StringWriter();

            List<string> lines = new List<string>();
            string current_line = "";
            int current_depth = 0;
            const int TabSpace = 4;
            CSharpSourceCode src;

            TargetLang lang;

            public CcWalker(CSharpSourceCode src, TargetLang lang) : base(SyntaxWalkerDepth.StructuredTrivia)
            {
                this.src = src;
                this.lang = lang;
            }

            string convert_type(string src)
            {
                if (lang == TargetLang.TypeScript)
                {
                    if (src.StartsWith("Vpn"))
                    {
                        src = "VPN." + src;
                    }

                    if (src == "int" || src == "uint" || src == "long" || src == "ulong")
                    {
                        src = "number";
                    }

                    if (src == "bool")
                    {
                        src = "boolean";
                    }

                    if (src == "DateTime")
                    {
                        src = "Date";
                    }
                }
                return src;
            }

            string convert_function(string src)
            {
                if (lang == TargetLang.TypeScript)
                {
                    if (src == "Console.WriteLine" || src == "print_object")
                    {
                        src = "console.log";
                    }

                    if (src.StartsWith("api.") || src.StartsWith("Test_"))
                    {
                        src = "await " + src;
                    }
                }
                return src;
            }

            void _emit_internal(string str, bool new_line)
            {
                if (string.IsNullOrEmpty(current_line))
                {
                    current_line += new string(' ', current_depth * TabSpace);
                }
                current_line += str;
                if (new_line)
                {
                    lines.Add(current_line);
                    current_line = "";
                }
            }

            void emit_line(string str = "") => emit(str + "\r\n");

            void emit(string str, bool new_line)
            {
                if (new_line == false)
                {
                    emit(str);
                }
                else
                {
                    emit_line(str);
                }
            }

            void emit(string str)
            {
                string tmp = "";
                for (int i = 0; i < str.Length; i++)
                {
                    char c = str[i];
                    if (c == '\r') { }
                    else if (c == '\n')
                    {
                        _emit_internal(tmp, true);
                        tmp = "";
                    }
                    else
                    {
                        tmp += c;
                    }
                }
                if (String.IsNullOrEmpty(tmp) == false)
                {
                    _emit_internal(tmp, false);
                }
            }

            public override void VisitMethodDeclaration(MethodDeclarationSyntax node)
            {
                if (node.Identifier.Text == "print_object") return;

                if (lang == TargetLang.TypeScript)
                {
                    emit_line();

                    var sem = src.Model.GetDeclaredSymbol(node);
                    string doc2 = sem.GetDocumentStr();
                    if (string.IsNullOrEmpty(doc2) == false)
                    {
                        emit_line($"/** {doc2} */");
                    }

                    emit("async function ");
                    emit(node.Identifier.Text);
                    Visit(node.ParameterList);
                    emit(": ");
                    emit("Promise<");
                    Visit(node.ReturnType);
                    emit(">");
                    emit_line("");

                    Visit(node.Body);
                }
                else
                {
                    emit("public");
                    emit(" ");
                    Visit(node.ReturnType);
                    emit(" ");
                    emit(node.Identifier.Text);
                    Visit(node.ParameterList);
                    emit_line("");

                    Visit(node.Body);
                }
            }

            public override void VisitParameter(ParameterSyntax node)
            {
                if (lang == TargetLang.TypeScript)
                {
                    emit($"{node.Identifier.Text}");
                    emit(": ");
                    Visit(node.Type);
                }
                else
                {
                    Visit(node.Type);
                    emit(" ");
                    emit($"{node.Identifier.Text}");
                }
            }

            public override void VisitParameterList(ParameterListSyntax node)
            {
                emit("(");
                int num = 0;
                foreach (ParameterSyntax p in node.Parameters)
                {
                    if (num >= 1)
                    {
                        emit(", ");
                    }

                    Visit(p);

                    num++;
                }
                emit(")");
            }

            public override void VisitArgumentList(ArgumentListSyntax node)
            {
                emit("(");
                int num = 0;
                foreach (ArgumentSyntax arg in node.Arguments)
                {
                    if (num >= 1)
                    {
                        emit(", ");
                    }

                    this.VisitArgument(arg);

                    num++;
                }
                emit(")");
            }

            public override void VisitAssignmentExpression(AssignmentExpressionSyntax node)
            {
                if (lang == TargetLang.TypeScript)
                {
                    if (node.Parent.Kind() == SyntaxKind.ObjectInitializerExpression)
                    {
                        Visit(node.Left);

                        emit(": ");

                        Visit(node.Right);
                    }
                    else
                    {
                        Visit(node.Left);

                        emit(" = ");

                        Visit(node.Right);
                    }
                }
                else
                {
                    Visit(node.Left);

                    emit(" = ");

                    Visit(node.Right);
                }
            }

            public override void VisitMemberAccessExpression(MemberAccessExpressionSyntax node)
            {
                Visit(node.Expression);

                emit(node.OperatorToken.Text);

                Visit(node.Name);
            }

            public override void VisitCastExpression(CastExpressionSyntax node)
            {
                if (lang == TargetLang.TypeScript)
                {
                    Visit(node.Expression);
                }
                else
                {
                    emit("(");
                    Visit(node.Type);
                    emit(")");
                    Visit(node.Expression);
                }
            }

            public override void VisitBreakStatement(BreakStatementSyntax node)
            {
                emit_line("break;");
            }

            public override void VisitReturnStatement(ReturnStatementSyntax node)
            {
                if (node.Expression == null)
                {
                    emit_line("return;");
                }
                else
                {
                    emit("return");
                    emit(" ");
                    Visit(node.Expression);
                    emit_line(";");
                }
            }

            public override void VisitForEachStatement(ForEachStatementSyntax node)
            {
                if (lang == TargetLang.TypeScript)
                {
                    emit("for (let ");
                    emit(node.Identifier.Text);
                    emit(" of ");
                    Visit(node.Expression);
                    emit_line(")");
                    Visit(node.Statement);
                }
                else
                {
                    emit("foreach (");

                    Visit(node.Type);

                    emit(" ");

                    emit(node.Identifier.Text);

                    emit(" in ");

                    Visit(node.Expression);

                    emit_line(")");

                    Visit(node.Statement);
                }
            }

            public override void VisitExpressionStatement(ExpressionStatementSyntax node)
            {
                Visit(node.Expression);

                emit_line(";");
            }

            public override void VisitConditionalExpression(ConditionalExpressionSyntax node)
            {
                Visit(node.Condition);
                emit(" ? ");
                Visit(node.WhenTrue);
                emit(" : ");
                Visit(node.WhenFalse);
            }

            public override void VisitIfStatement(IfStatementSyntax node)
            {
                emit("if (");
                Visit(node.Condition);
                emit_line(")");

                Visit(node.Statement);

                if (node.Else != null)
                {
                    if (node.Else.Statement is IfStatementSyntax)
                    {
                        emit("else ");
                    }
                    else
                    {
                        emit_line("else");
                    }

                    Visit(node.Else.Statement);
                }
            }

            public override void VisitInitializerExpression(InitializerExpressionSyntax node)
            {
                if (lang == TargetLang.TypeScript)
                {
                    if (node.Kind() == SyntaxKind.ArrayInitializerExpression)
                    {
                        bool is_byte_array = false;

                        if (node.Parent.Kind() == SyntaxKind.ArrayCreationExpression &&
                            ((ArrayCreationExpressionSyntax)node.Parent).Type.ElementType.ToString() == "byte")
                        {
                            is_byte_array = true;
                        }

                        if (is_byte_array)
                        {
                            emit("new Uint8Array(");
                        }

                        emit("[ ");
                        current_depth++;

                        foreach (var exp in node.Expressions)
                        {
                            this.Visit(exp);

                            emit(", ");
                        }

                        current_depth--;
                        emit(" ]");

                        if (is_byte_array)
                        {
                            emit(")");
                        }
                    }
                    else
                    {
                        emit_line("{");
                        current_depth++;

                        foreach (var exp in node.Expressions)
                        {
                            this.Visit(exp);

                            emit_line(",");
                        }

                        current_depth--;
                        emit("}");
                    }
                }
                else
                {
                    if (node.Kind() == SyntaxKind.ArrayInitializerExpression)
                    {
                        emit("{ ");
                        current_depth++;

                        foreach (var exp in node.Expressions)
                        {
                            this.Visit(exp);

                            emit(", ");
                        }

                        current_depth--;
                        emit(" }");
                    }
                    else
                    {
                        emit_line("{");
                        current_depth++;

                        foreach (var exp in node.Expressions)
                        {
                            this.Visit(exp);

                            emit_line(",");
                        }

                        current_depth--;
                        emit("}");
                    }
                }
            }

            public override void VisitArrayCreationExpression(ArrayCreationExpressionSyntax node)
            {
                if (lang == TargetLang.TypeScript)
                {
                    var type = node.Type;

                    if (node.Initializer != null)
                    {
                        emit(" ");
                        Visit(node.Initializer);
                    }
                    else
                    {
                        emit("[]");
                    }
                }
                else
                {
                    var type = node.Type;

                    emit("new ");

                    Visit(node.Type);

                    if (node.Initializer != null)
                    {
                        emit(" ");
                        Visit(node.Initializer);
                    }
                }
            }

            public override void VisitObjectCreationExpression(ObjectCreationExpressionSyntax node)
            {
                if (lang == TargetLang.TypeScript)
                {
                    var type = (IdentifierNameSyntax)node.Type;

                    if (node.Initializer == null)
                    {
                        emit("new ");
                        Visit(node.Type);
//                        emit($"new {type.Identifier.Text}");

                        Visit(node.ArgumentList);
                    }
                    else
                    {
                        emit("new ");
                        Visit(node.Type);
                        emit_line("(");
                        Visit(node.Initializer);
                        emit(")");
                    }
                }
                else
                {
                    var type = (IdentifierNameSyntax)node.Type;

                    emit($"new {type.Identifier.Text}");

                    Visit(node.ArgumentList);

                    if (node.Initializer != null)
                    {
                        emit_line("");
                        Visit(node.Initializer);
                    }
                }
            }

            public override void VisitLiteralExpression(LiteralExpressionSyntax node)
            {
                emit(node.Token.Text);
            }

            public override void VisitParenthesizedExpression(ParenthesizedExpressionSyntax node)
            {
                emit("(");
                base.Visit(node.Expression);
                emit(")");
            }

            public override void VisitBinaryExpression(BinaryExpressionSyntax node)
            {
                base.Visit(node.Left);
                emit($" {node.OperatorToken.Text} ");
                base.Visit(node.Right);
            }

            public override void VisitIdentifierName(IdentifierNameSyntax node)
            {
                string name = node.Identifier.Text;

                if (node.Parent.Kind() == SyntaxKind.VariableDeclaration
                     || node.Parent.Kind() == SyntaxKind.MethodDeclaration
                     || node.Parent.Kind() == SyntaxKind.SimpleMemberAccessExpression
                     || node.Parent.Kind() == SyntaxKind.ForEachStatement
                     || node.Parent.Kind() == SyntaxKind.Parameter
                     || node.Parent.Kind() == SyntaxKind.ObjectCreationExpression)
                {
                    name = convert_type(name);
                }

                var sym = src.Model.GetSymbolInfo(node);
                string json_name = "";
                bool json_name_has_special_char = false;
                var atts = sym.Symbol.GetAttributes();
                var y = atts.Where(x => x.AttributeClass.Name == "JsonPropertyAttribute").FirstOrDefault();
                if (y != null)
                {
                    json_name = y.ConstructorArguments.FirstOrDefault().Value.ToString();
                    if (json_name.IndexOf(':') != -1 || json_name.IndexOf('.') != -1) json_name_has_special_char = true;
                }

                string field_name = name;
                if (lang == TargetLang.TypeScript)
                {
                    if (string.IsNullOrEmpty(json_name) == false) field_name = json_name;
                    if (json_name_has_special_char) field_name = $"[\"{json_name}\"]";
                }

                emit(field_name);
            }
            
            public override void VisitInvocationExpression(InvocationExpressionSyntax node)
            {
                string func_name = node.Expression.ToString();
                func_name = convert_function(func_name);

                if (lang == TargetLang.TypeScript)
                {
                    if (func_name == "rand.Next")
                    {
                        string a = node.ArgumentList.Arguments[0].ToString();
                        string b = node.ArgumentList.Arguments[1].ToString();
                        emit($"Math.floor((Math.random() * ({b} - {a})) + {a})");
                        return;
                    }

                    if (func_name == "System.Threading.Thread.Sleep")
                    {
                        string a = node.ArgumentList.Arguments[0].ToString();
                        emit($"await new Promise((r) => setTimeout(r, {a}))");
                        return;
                    }
                }

                emit(func_name);

                Visit(node.ArgumentList);
            }

            public override void VisitPredefinedType(PredefinedTypeSyntax node)
            {
                string name = node.Keyword.Text;
                name = convert_type(name);
                emit(name);
            }

            public override void VisitArrayRankSpecifier(ArrayRankSpecifierSyntax node)
            {
                emit("[");

                int num = 0;

                foreach (ExpressionSyntax exp in node.Sizes)
                {
                    if (num >= 1)
                    {
                        emit(",");
                    }

                    Visit(exp);

                    num++;
                }

                emit("]");
            }

            public override void VisitConstructorDeclaration(ConstructorDeclarationSyntax node)
            {
                /*foreach (var statement in node.Body.Statements)
                {
                    Visit(statement);
                }*/
            }

            public override void VisitArrayType(ArrayTypeSyntax node)
            {
                Visit(node.ElementType);

                foreach (var rank in node.RankSpecifiers)
                {
                    Visit(rank);
                }
            }

            public void VisitVariableDeclarator(VariableDeclaratorSyntax node, TypeSyntax type)
            {
                if (lang == TargetLang.TypeScript)
                {
//                    if (node.Parent.Parent.Kind() == SyntaxKind.LocalDeclarationStatement)
                    {
                        emit("let ");
                    }

                    emit($"{node.Identifier.Text}");

                    emit(": ");

                    var type_dec = src.Model.GetTypeInfo(type);

                    if (type is PredefinedTypeSyntax)
                    {
                        Visit(type);
                    }
                    else if (type is ArrayTypeSyntax)
                    {
                        Visit(type);
                    }
                    else if (type is IdentifierNameSyntax)
                    {
                        Visit(type);
                    }
                    else
                    {
                        throw new ApplicationException($"VisitVariableDeclarator: {type.GetType().ToString()}");
                    }

                    if (node.Initializer != null)
                    {
                        emit(" = ");

                        var value = node.Initializer.Value;

                        base.Visit(value);
                    }

                    emit_line(";");
                }
                else
                {
                    var type_dec = src.Model.GetTypeInfo(type);

                    if (type is PredefinedTypeSyntax)
                    {
                        Visit(type);
                    }
                    else if (type is ArrayTypeSyntax)
                    {
                        Visit(type);
                    }
                    else if (type is IdentifierNameSyntax)
                    {
                        Visit(type);
                    }
                    else
                    {
                        throw new ApplicationException($"VisitVariableDeclarator: {type.GetType().ToString()}");
                    }

                    emit($" {node.Identifier.Text}");

                    if (node.Initializer != null)
                    {
                        emit(" = ");

                        var value = node.Initializer.Value;

                        base.Visit(value);
                    }

                    emit_line(";");
                }
            }

            public override void VisitVariableDeclaration(VariableDeclarationSyntax node)
            {
                foreach (var v in node.Variables)
                {
                    VisitVariableDeclarator(v, node.Type);
                }
            }

            public override void VisitLocalDeclarationStatement(LocalDeclarationStatementSyntax node)
            {
                Visit(node.Declaration);
            }

            public override void VisitFieldDeclaration(FieldDeclarationSyntax node)
            {
                //Visit(node.Declaration);
            }

            public override void VisitBlock(BlockSyntax node)
            {
                emit_line("{");
                current_depth++;

                foreach (var statement in node.Statements)
                {
                    Visit(statement);
                }

                current_depth--;
                emit_line("}");
            }

            public override void VisitClassDeclaration(ClassDeclarationSyntax node)
            {
                if (lang == TargetLang.TypeScript)
                {
                    base.VisitClassDeclaration(node);
                }
                else
                {
                    emit_line($"class {node.Identifier.Text}");
                    emit_line("{");

                    current_depth++;

                    base.VisitClassDeclaration(node);

                    current_depth--;

                    emit_line("}");
                }
            }

            public override string ToString()
            {
                StringWriter w = new StringWriter();
                this.lines.ForEach(x => w.WriteLine(x));
                if (String.IsNullOrEmpty(this.current_line) == false) w.WriteLine(this.current_line);
                return w.ToString();
            }
        }

        void generate_tests(GeneratedCodeForLang ret)
        {
            var test_class = cs_tests.Root.DescendantNodes().OfType<ClassDeclarationSyntax>().Where(c => c.Identifier.Text == "VPNRPCTest").First();

            CcWalker ts_walker = new CcWalker(cs_tests, TargetLang.TypeScript);
            ts_walker.Visit(test_class);
            ret.TypeScript.Tests.PartList.Add(new GeneratedCodePart() { Seq = 0, Text = ts_walker.ToString() });
        }

        void doc_write_parameters(StringWriter w, RpcTypeInfo type_info)
        {
            List<RpcTypeParameterInfo> plist = new List<RpcTypeParameterInfo>();

            foreach (RpcTypeParameterInfo p in type_info.Params)
            {
                plist.Add(p);
            }

            foreach (string subtype in type_info.SubTypes)
            {
                foreach (RpcTypeParameterInfo p in rpc_type_list[subtype].Params)
                {
                    plist.Add(p);
                }
            }

            w.WriteLine("Name | Type | Description");
            w.WriteLine("--- | --- | ---");
            foreach (RpcTypeParameterInfo p in plist)
            {
                w.WriteLine($"`{p.Name}` | {p.Type} | {p.Description}");
            }
        }

        void doc_write_function(StringWriter w, RpcInfo rpc)
        {
            string func_summary = rpc.Symbol.GetDocumentStr();
            int index = func_summary.IndexOf(".");
            if (index != -1) func_summary = func_summary.Substring(0, index + 1);
            func_summary = func_summary.TrimEnd('.');

            w.WriteLine($"<a id=\"{rpc.Name.ToLowerInvariant()}\"></a>");
            w.WriteLine($"## \"{rpc.Name}\" RPC API - {func_summary}");

            w.WriteLine("### Description");

            w.WriteLine(rpc.Symbol.GetDocumentStr());

            var model = cs_tests.Model;

            var func = cs_tests.Root.DescendantNodes().OfType<MethodDeclarationSyntax>()
                .Where(f => f.Identifier.Text == "Test_" + rpc.Name)
                .Single();

            var fields = func.DescendantNodes().OfType<InitializerExpressionSyntax>()
                .Where(i => i.Kind() == SyntaxKind.ObjectInitializerExpression)
                .SelectMany(o => o.DescendantNodes().OfType<AssignmentExpressionSyntax>())
                .Where(a => a.Kind() == SyntaxKind.SimpleAssignmentExpression)
                .Select(a => (a.Left as IdentifierNameSyntax));

            foreach (var field in fields)
            {
                string json_name = field.Identifier.Text;
                var sym = model.GetSymbolInfo(field);

                var atts = sym.Symbol.GetAttributes();
                var y = atts.Where(x => x.AttributeClass.Name == "JsonPropertyAttribute").FirstOrDefault();
                if (y != null)
                {
                    json_name = y.ConstructorArguments.FirstOrDefault().Value.ToString();
                }

                rpc.InputParamMembers.Add(json_name);
            }

            Type obj_type = Type.GetType("SoftEther.VPNServerRpc." + rpc.TypeName);

            object in_object = Activator.CreateInstance(obj_type);
            object out_object = Activator.CreateInstance(obj_type);

            JsonRpcRequest rpc_in = new JsonRpcRequest() { Method = rpc.Name, Params = in_object, Id = "rpc_call_id", };
            Type rpc_out_type = typeof(JsonRpcResponse<>).MakeGenericType(obj_type);
            var rpc_out = Activator.CreateInstance(rpc_out_type);

            rpc_out_type.GetProperty("Id").SetValue(rpc_out, "rpc_call_id");
            rpc_out_type.GetProperty("Result").SetValue(rpc_out, out_object);

            sample_fill_object(in_object);
            sample_fill_object(out_object);

            JsonSerializerSettings rpc_in_settings = new JsonSerializerSettings()
            {
                MaxDepth = 8,
                NullValueHandling = NullValueHandling.Include,
                ReferenceLoopHandling = ReferenceLoopHandling.Error,
                PreserveReferencesHandling = PreserveReferencesHandling.None,
                ContractResolver = new JSonInputContractResolver(rpc),
            };

            JsonSerializerSettings rpc_out_settings = new JsonSerializerSettings()
            {
                MaxDepth = 8,
                NullValueHandling = NullValueHandling.Include,
                ReferenceLoopHandling = ReferenceLoopHandling.Error,
                PreserveReferencesHandling = PreserveReferencesHandling.None,
                ContractResolver = new JSonOutputContractResolver(rpc),
            };

            string in_str = JsonConvert.SerializeObject(rpc_in, Formatting.Indented, rpc_in_settings);
            string out_str = JsonConvert.SerializeObject(rpc_out, Formatting.Indented, rpc_out_settings);

            w.WriteLine();
            w.WriteLine("### Input JSON-RPC Format");
            w.WriteLine("```json");
            w.WriteLine(in_str);
            w.WriteLine("```");

            w.WriteLine();
            w.WriteLine("### Output JSON-RPC Format");
            w.WriteLine("```json");
            w.WriteLine(out_str);
            w.WriteLine("```");

            w.WriteLine();
            w.WriteLine("### Parameters");
            w.WriteLine();
            doc_write_parameters(w, rpc_type_list[rpc.TypeName]);

            //w.WriteLine("<BR>  ");
            w.WriteLine();
        }

        class JSonOutputContractResolver : DefaultContractResolver
        {
            RpcInfo rpc_info;

            public JSonOutputContractResolver(RpcInfo info) : base()
            {
                this.rpc_info = info;
            }

            protected override JsonProperty CreateProperty(MemberInfo member, MemberSerialization memberSerialization)
            {
                if (member.Name == "Error") return null;
                JsonProperty ret = base.CreateProperty(member, memberSerialization);
                return ret;
            }
        }


        class JSonInputConverter : JsonConverter
        {
            RpcInfo rpc_info;

            public JSonInputConverter(RpcInfo info)
            {
                this.rpc_info = info;
            }

            public override bool CanRead => false;

            public override bool CanConvert(Type objectType)
            {
                return true;
            }

            public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
            {
                throw new NotImplementedException();
            }

            public override void WriteJson(JsonWriter w, object value, JsonSerializer serializer)
            {
                JToken t = JToken.FromObject(value);
                List<JProperty> a = new List<JProperty>();
                bool all = false;
                if (rpc_info.Name == "SetHubLog") all = true;

                foreach (var p1 in t.Children<JProperty>())
                {
                    foreach (var p2 in p1.Children<JProperty>())
                    {
                        if (rpc_info.InputParamMembers.Contains(p2.Name) == false) a.Add(p2);
                    }
                    if (rpc_info.InputParamMembers.Contains(p1.Name) == false) a.Add(p1);
                }
                if (all == false)
                {
                    foreach (var p in a)
                    {
                        try
                        {
                            p.Remove();
                        }
                        catch
                        {
                        }
                    }
                }
                t.WriteTo(w);
            }
        }

        class JSonInputContractResolver : DefaultContractResolver
        {
            RpcInfo rpc_info;

            public JSonInputContractResolver(RpcInfo info) : base()
            {
                this.rpc_info = info;
            }

            protected override JsonProperty CreateProperty(MemberInfo member, MemberSerialization memberSerialization)
            {
                JsonProperty ret = base.CreateProperty(member, memberSerialization);
                ret.Converter = new JSonInputConverter(this.rpc_info);
                return ret;
            }
        }

        void sample_fill_object(object o)
        {
            Type t = o.GetType();

            var fields = t.GetFields();
            foreach (var field in fields)
            {
                Type t2 = field.FieldType;
                object v = null;

                if (t2 == typeof(string))
                {
                    string tmp = field.Name.ToLowerInvariant();
                    if (tmp.EndsWith("_str") || tmp.EndsWith("_utf")) tmp = tmp.Substring(0, tmp.Length - 4);
                    if (tmp.EndsWith("_ip"))
                    {
                        if (tmp.IndexOf("mask", StringComparison.InvariantCultureIgnoreCase) == -1)
                            tmp = "192.168.0.1";
                        else
                            tmp = "255.255.255.255";
                    }
                    v = tmp;
                }
                else if (t2 == typeof(uint))
                    v = (uint)0;
                else if (t2 == typeof(ulong))
                    v = (ulong)0;
                else if (t2 == typeof(bool))
                    v = (bool)false;
                else if (t2 == typeof(byte[]))
                    v = Encoding.UTF8.GetBytes("Hello World");
                else if (t2 == typeof(DateTime))
                    v = new DateTime(DateTime.Now.Year + 1, 8, 1, 12, 24, 36, 123);
                else if (t2.IsEnum)
                {
                    v = (int)0;
                }
                else if (t2.IsArray)
                {
                    if (t2 == typeof(uint[]))
                    {
                        v = new uint[] { 1, 2, 3 };
                    }
                    else
                    {
                        if (t2.GetArrayRank() != 1) throw new ApplicationException("Array rank != 1");
                        Type obj_type = t2.GetElementType();

                        if (obj_type.IsEnum)
                        {
                            v = new int[] { 1, 2, 3 };
                        }
                        else
                        {
                            int num = 3;

                            if (field.Name.IndexOf("single", StringComparison.CurrentCultureIgnoreCase) != -1)
                            {
                                num = 1;
                            }

                            object list = Activator.CreateInstance(typeof(List<>).MakeGenericType(obj_type));

                            for (int i = 0; i < num; i++)
                            {
                                object a = Activator.CreateInstance(obj_type);
                                sample_fill_object(a);

                                list.GetType().GetMethod("Add").Invoke(list, new object[] { a });
                            }

                            v = list.GetType().GetMethod("ToArray").Invoke(list, new object[] { } );
                        }
                    }
                }
                else if (t2.Name.StartsWith("Vpn"))
                {
                    Type obj_type = Type.GetType("SoftEther.VPNServerRpc." + t2.Name);
                    v = Activator.CreateInstance(obj_type);
                    sample_fill_object(v);
                }
                else
                {
                    throw new ApplicationException($"sample_fill_object: type: {t2.ToString()}");
                }

                field.SetValue(o, v);
            }
        }

        void generate_documents(GeneratedCodeForLang ret)
        {
            StringWriter w = new StringWriter();

            string doc_txt = read_text_resource("doc.txt");
            w.WriteLine(doc_txt);

            w.WriteLine("## Table of contents");
            foreach (RpcInfo rpc in rpc_list.Values)
            {
                string func_summary = rpc.Symbol.GetDocumentStr();
                int index = func_summary.IndexOf(".");
                if (index != -1) func_summary = func_summary.Substring(0, index + 1);
                func_summary = func_summary.TrimEnd('.');

                w.WriteLine($"- [{rpc.Name} - {func_summary}](#{rpc.Name.ToLowerInvariant()})");

            }

            w.WriteLine();
            w.WriteLine("***");

            foreach (RpcInfo rpc in rpc_list.Values)
            {
                if (rpc.Name.IndexOf("Vgs", StringComparison.Ordinal) == -1)
                {
                    doc_write_function(w, rpc);

                    w.WriteLine("***");
                }
            }

            w.WriteLine($"Automatically generated at {timestamp.ToString("yyyy-MM-dd HH:mm:ss")} by vpnserver-jsonrpc-codegen.  ");
            w.WriteLine("Copyright (c) 2014-" + DateTime.Now.Year + " [SoftEther VPN Project](https://www.softether.org/) under the Apache License 2.0.  ");
            w.WriteLine();

            ret.DocsRpc = w.ToString();
        }

        public GeneratedCodeForLang GenerateCodes()
        {
            GeneratedCodeForLang ret = new GeneratedCodeForLang();

            generate_stubs(ret);

            generate_tests(ret);

            generate_types(ret);

            generate_documents(ret);

            return ret;
        }

        public void GenerateAndSaveCodes(string output_dir)
        {
            CodeGenUtil.MakeDir(output_dir);

            WriteLine($"GenerateAndSaveCodes(): output_dir = '{output_dir}'");
            WriteLine();
            WriteLine("Generating codes ...");
            GeneratedCodeForLang codes = GenerateCodes();
            WriteLine("Generating codes: done.");
            WriteLine();

            output_docs(codes, output_dir);

            output_csharp(Path.Combine(output_dir, "vpnserver-jsonrpc-client-csharp"));

            output_typescript(codes.TypeScript, Path.Combine(output_dir, "vpnserver-jsonrpc-client-typescript"));
        }

        static Assembly this_assembly = Assembly.GetExecutingAssembly();
        static string read_text_resource(string name)
        {
            var x = this_assembly.GetManifestResourceNames();
            string resourceName = this_assembly.GetManifestResourceNames().Single(str => str.EndsWith(name));
            using (Stream stream = this_assembly.GetManifestResourceStream(resourceName))
            {
                using (StreamReader reader = new StreamReader(stream))
                {
                    return reader.ReadToEnd();
                }
            }
        }

        static string read_text_file(string name)
        {
            using (Stream stream = File.OpenRead(name))
            {
                using (StreamReader reader = new StreamReader(stream))
                {
                    return reader.ReadToEnd();
                }
            }
        }

        static string replace_strings(string src, params string[] replace_list)
        {
            int i;
            for (i = 0; i < replace_list.Length / 2; i++)
            {
                string s1 = replace_list[i * 2];
                string s2 = replace_list[i * 2 + 1];
                src = src.Replace(s1, s2, StringComparison.InvariantCultureIgnoreCase);
            }
            return src;
        }

        static string normalize_crlf(string src, string crlf)
        {
            StringReader r = new StringReader(src);
            StringWriter w = new StringWriter();
            w.NewLine = crlf;
            while (true)
            {
                string line = r.ReadLine();
                if (line == null) break;
                w.WriteLine(line);
            }
            return w.ToString();
        }

        static void normalize(ref string str, string crlf, params string[] replace_list)
        {
            str = normalize_crlf(replace_strings(str, replace_list), crlf);
        }

        static void save(string path, string body, bool bom)
        {
            string dir_name = Path.GetDirectoryName(path);
            CodeGenUtil.MakeDir(dir_name);

            if (bom)
                File.WriteAllText(path, body, Encoding.UTF8);
            else
                File.WriteAllText(path, body);
        }

        DateTime timestamp = DateTime.Now;

        void output_docs(GeneratedCodeForLang c, string output_dir)
        {
            CodeGenUtil.MakeDir(output_dir);

            save(Path.Combine(output_dir, "README.md"), c.DocsRpc, true);

            var pipeline = new MarkdownPipelineBuilder().UseAdvancedExtensions().Build();

            string md_html_body = Markdown.ToHtml(c.DocsRpc, pipeline);

            string html = read_text_resource("md_html.html");

            string[] replace_list =
            {
                "__BODY__", md_html_body,
            };

            normalize(ref html, "\r\n", replace_list);

            save(Path.Combine(output_dir, "README.html"), html, true);
            save(Path.Combine(CodeGenUtil.OutputDir_HamCore, "vpnserver_api_doc.html"), html, true);
        }

        void output_typescript(GeneratedCode c, string output_dir)
        {
            CodeGenUtil.MakeDir(output_dir);

            string ts_rpc = read_text_resource("ts_rpc.txt");
            string ts_test = read_text_resource("ts_test.txt");

            string[] replace_list =
                {
                    "__YEAR__", timestamp.Year.ToString(),
                    "__TESTS__", c.Tests.ToString(),
                    "__STUBS__", c.Stubs.ToString(),
                    "__TYPES__", c.Types.ToString(),
                    "__TIMESTAMP__", timestamp.ToString("yyyy-MM-dd HH:mm:ss"),
            };

            normalize(ref ts_rpc, "\n", replace_list);
            normalize(ref ts_test, "\n", replace_list);

            save(Path.Combine(output_dir, "vpnrpc.ts"), ts_rpc, true);
            save(Path.Combine(output_dir, "sample.ts"), ts_test, true);

            save(Path.Combine(output_dir + "/../vpnserver-jsonrpc-client-nodejs-package/src/", "vpnrpc.ts"), ts_rpc, true);
            save(Path.Combine(output_dir + "/../vpnserver-jsonrpc-client-nodejs-package/src/", "sample.ts"), ts_test, true);
        }

        void output_csharp(string output_dir)
        {
            CodeGenUtil.MakeDir(output_dir);
            
            string cs_proj = read_text_resource("cs_proj.txt");
            string cs_sln = read_text_resource("cs_sln.txt");
            string cs_main = read_text_resource("cs_main.txt");

            string cs_code_jsonrpc = read_text_file(Path.Combine(CodeGenUtil.ProjectDir,
                @"VpnServerRpc/JsonRpc.cs"));

            string cs_code_vpnserver_rpc = read_text_file(Path.Combine(CodeGenUtil.ProjectDir,
                @"VpnServerRpc/VPNServerRpc.cs"));

            string cs_code_vpnserver_rpc_types = read_text_file(Path.Combine(CodeGenUtil.ProjectDir,
                @"VpnServerRpc/VPNServerRpcTypes.cs"));

            string cs_code_vpnserver_rpc_test = read_text_file(Path.Combine(CodeGenUtil.ProjectDir,
                @"VpnServerRpcTest/VpnServerRpcTest.cs"));

            string[] replace_list =
                {
                    "__YEAR__", timestamp.Year.ToString(),
                    "__TIMESTAMP__", timestamp.ToString("yyyy-MM-dd HH:mm:ss"),
            };

            normalize(ref cs_main, "\r\n", replace_list);
            normalize(ref cs_proj, "\r\n", replace_list);
            normalize(ref cs_sln, "\r\n", replace_list);
            normalize(ref cs_code_jsonrpc, "\r\n", replace_list);
            normalize(ref cs_code_vpnserver_rpc, "\r\n", replace_list);
            normalize(ref cs_code_vpnserver_rpc_types, "\r\n", replace_list);
            normalize(ref cs_code_vpnserver_rpc_test, "\r\n", replace_list);

            save(Path.Combine(output_dir, "vpnserver-jsonrpc-client-csharp.csproj"),
                cs_proj, true);

            save(Path.Combine(output_dir, "vpnserver-jsonrpc-client-csharp.sln"),
                cs_sln, true);

            save(Path.Combine(output_dir, @"rpc-stubs\JsonRpc.cs"),
                cs_code_jsonrpc, true);

            save(Path.Combine(output_dir, @"rpc-stubs\VPNServerRpc.cs"),
                cs_code_vpnserver_rpc, true);

            save(Path.Combine(output_dir, @"rpc-stubs\VPNServerRpcTypes.cs"),
                cs_code_vpnserver_rpc_types, true);

            save(Path.Combine(output_dir, @"sample\VpnServerRpcTest.cs"),
                cs_code_vpnserver_rpc_test, true);

            save(Path.Combine(output_dir, @"sample\Main.cs"),
                cs_main, true);
        }

        public void Test()
        {
            GeneratedCodeForLang ret = GenerateCodes();

            Console.WriteLine(ret.TypeScript.ToString());

            return;
            var model = cs_types.Model;

            var type_classes = cs_types.Root.DescendantNodes()
                .OfType<ClassDeclarationSyntax>();

            foreach (ClassDeclarationSyntax v in type_classes)
            {
                WriteLine(v.Identifier.Text);

                var info = model.GetDeclaredSymbol(v);

                var x = info.GetMembers();

                foreach (var y in x)
                {
                    WriteLine(y.Name);
                }

                break;
            }

            Console.WriteLine();
        }
    }
}
