using dnlib.DotNet;
using dnlib.DotNet.Writer;
using System;
using System.IO;

internal class Program
{
    public static bool IsWinForms = false;
    public static string FileExtension = string.Empty;

    private static void Main()
    {

        Console.WriteLine(@"
     _    _   _ _____ ___  __     ____  __  
    / \  | \ | |_   _|_ _| \ \   / /  \/  | 
   / _ \ |  \| | | |  | |   \ \ / /| |\/| | 
  / ___ \| |\  | | |  | |    \ V / | |  | | 
 /_/   \_\_| \_| |_| |___|    \_/  |_|  |_| 
                                            
");

        Console.WriteLine("Drag your file:");

        string file = Console.ReadLine().Replace("\"", "");
        FileExtension = Path.GetExtension(file);
        ModuleDefMD module = ModuleDefMD.Load(file);
        string fileName = Path.GetFileNameWithoutExtension(file);
        Execute(module);
        var opts = new ModuleWriterOptions(module);
        opts.Logger = DummyLogger.NoThrowInstance;
        string outputPath = $@"C:\Users\{Environment.UserName}\Desktop\{fileName}-nigger{FileExtension}";
        module.Write(outputPath, opts);
        Console.WriteLine("Output file saved as: " + outputPath);
        Console.WriteLine("Press any key to exit...");
        Console.ReadKey();
    }

    private static void Execute(ModuleDefMD module)
    {
        Antivm.Execute(module);

        Console.WriteLine();
        Console.WriteLine("Obfuscation Complete!");
    }
}
