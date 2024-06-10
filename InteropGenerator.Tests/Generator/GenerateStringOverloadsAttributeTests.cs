using InteropGenerator.Tests.Helpers;
using Xunit;
using VerifyIG = InteropGenerator.Tests.Helpers.IncrementalGeneratorVerifier<InteropGenerator.Generator.InteropGenerator>;

namespace InteropGenerator.Tests.Generator;

public class GenerateStringOverloadsAttributeTests {
    [Fact]
    public async Task GenerateStringOverloads() {
        const string code = """
                            [global::System.Runtime.InteropServices.StructLayout(global::System.Runtime.InteropServices.LayoutKind.Explicit)]
                            [GenerateInterop]
                            public unsafe partial struct TestStruct
                            {
                                [GenerateStringOverloads]
                                public int TestFunction(int argOne, byte* stringArg) { return 0; }
                            }
                            """;

        const string result = """
                              // <auto-generated/>
                              unsafe partial struct TestStruct
                              {
                                  public int TestFunction(int argOne, string stringArg)
                                  {
                                      int stringArgUTF8StrLen = global::System.Text.Encoding.UTF8.GetByteCount(stringArg);
                                      Span<byte> stringArgBytes = stringArgUTF8StrLen <= 512 ? stackalloc byte[stringArgUTF8StrLen + 1] : new byte[stringArgUTF8StrLen + 1];
                                      global::System.Text.Encoding.UTF8.GetBytes(stringArg, stringArgBytes);
                                      stringArgBytes[stringArgUTF8StrLen] = 0;
                                      fixed (byte* stringArgPtr = stringArgBytes)
                                      {
                                          return TestFunction(argOne, stringArgPtr);
                                      }
                                  }
                                  public int TestFunction(int argOne, ReadOnlySpan<byte> stringArg)
                                  {
                                      fixed (byte* stringArgPtr = stringArg)
                                      {
                                          return TestFunction(argOne, stringArgPtr);
                                      }
                                  }
                              }
                              """;

        await VerifyIG.VerifyGeneratorAsync(
            code,
            ("TestStruct.InteropGenerator.g.cs", result));
    }
    
    [Fact]
    public async Task GenerateStringOverloadsObsolete() {
        const string code = """
                            [global::System.Runtime.InteropServices.StructLayout(global::System.Runtime.InteropServices.LayoutKind.Explicit)]
                            [GenerateInterop]
                            public unsafe partial struct TestStruct
                            {
                                [Obsolete("This function is obsolete")]
                                [GenerateStringOverloads]
                                public int TestFunction(int argOne, byte* stringArg) { return 0; }
                            }
                            """;

        const string result = """
                              // <auto-generated/>
                              unsafe partial struct TestStruct
                              {
                                  [global::System.ObsoleteAttribute("This function is obsolete", false)]
                                  public int TestFunction(int argOne, string stringArg)
                                  {
                                      int stringArgUTF8StrLen = global::System.Text.Encoding.UTF8.GetByteCount(stringArg);
                                      Span<byte> stringArgBytes = stringArgUTF8StrLen <= 512 ? stackalloc byte[stringArgUTF8StrLen + 1] : new byte[stringArgUTF8StrLen + 1];
                                      global::System.Text.Encoding.UTF8.GetBytes(stringArg, stringArgBytes);
                                      stringArgBytes[stringArgUTF8StrLen] = 0;
                                      fixed (byte* stringArgPtr = stringArgBytes)
                                      {
                                          return TestFunction(argOne, stringArgPtr);
                                      }
                                  }
                                  [global::System.ObsoleteAttribute("This function is obsolete", false)]
                                  public int TestFunction(int argOne, ReadOnlySpan<byte> stringArg)
                                  {
                                      fixed (byte* stringArgPtr = stringArg)
                                      {
                                          return TestFunction(argOne, stringArgPtr);
                                      }
                                  }
                              }
                              """;

        await VerifyIG.VerifyGeneratorAsync(
            code,
            ("TestStruct.InteropGenerator.g.cs", result));
    }    

    [Fact]
    public async Task GenerateStringOverloadsWithDefaultValue() {
        const string code = """
                            [global::System.Runtime.InteropServices.StructLayout(global::System.Runtime.InteropServices.LayoutKind.Explicit)]
                            [GenerateInterop]
                            public unsafe partial struct TestStruct
                            {
                                [GenerateStringOverloads]
                                public int TestFunction(byte* stringArg, int intArg = 7) { return 0; }
                            }
                            """;

        const string result = """
                              // <auto-generated/>
                              unsafe partial struct TestStruct
                              {
                                  public int TestFunction(string stringArg, int intArg = 7)
                                  {
                                      int stringArgUTF8StrLen = global::System.Text.Encoding.UTF8.GetByteCount(stringArg);
                                      Span<byte> stringArgBytes = stringArgUTF8StrLen <= 512 ? stackalloc byte[stringArgUTF8StrLen + 1] : new byte[stringArgUTF8StrLen + 1];
                                      global::System.Text.Encoding.UTF8.GetBytes(stringArg, stringArgBytes);
                                      stringArgBytes[stringArgUTF8StrLen] = 0;
                                      fixed (byte* stringArgPtr = stringArgBytes)
                                      {
                                          return TestFunction(stringArgPtr, intArg);
                                      }
                                  }
                                  public int TestFunction(ReadOnlySpan<byte> stringArg, int intArg = 7)
                                  {
                                      fixed (byte* stringArgPtr = stringArg)
                                      {
                                          return TestFunction(stringArgPtr, intArg);
                                      }
                                  }
                              }
                              """;

        await VerifyIG.VerifyGeneratorAsync(
            code,
            ("TestStruct.InteropGenerator.g.cs", result));
    }

    [Fact]
    public async Task GenerateMultipleStringOverloads() {
        const string code = """
                            [global::System.Runtime.InteropServices.StructLayout(global::System.Runtime.InteropServices.LayoutKind.Explicit)]
                            [GenerateInterop]
                            public unsafe partial struct TestStruct
                            {
                                [GenerateStringOverloads]
                                public int TestFunction(int argOne, byte* stringArg, byte* stringArgTwo) { return 0; }
                            }
                            """;

        const string result = """
                              // <auto-generated/>
                              unsafe partial struct TestStruct
                              {
                                  public int TestFunction(int argOne, string stringArg, string stringArgTwo)
                                  {
                                      int stringArgUTF8StrLen = global::System.Text.Encoding.UTF8.GetByteCount(stringArg);
                                      Span<byte> stringArgBytes = stringArgUTF8StrLen <= 512 ? stackalloc byte[stringArgUTF8StrLen + 1] : new byte[stringArgUTF8StrLen + 1];
                                      global::System.Text.Encoding.UTF8.GetBytes(stringArg, stringArgBytes);
                                      stringArgBytes[stringArgUTF8StrLen] = 0;
                                      int stringArgTwoUTF8StrLen = global::System.Text.Encoding.UTF8.GetByteCount(stringArgTwo);
                                      Span<byte> stringArgTwoBytes = stringArgTwoUTF8StrLen <= 512 ? stackalloc byte[stringArgTwoUTF8StrLen + 1] : new byte[stringArgTwoUTF8StrLen + 1];
                                      global::System.Text.Encoding.UTF8.GetBytes(stringArgTwo, stringArgTwoBytes);
                                      stringArgTwoBytes[stringArgTwoUTF8StrLen] = 0;
                                      fixed (byte* stringArgPtr = stringArgBytes)
                                      {
                                          fixed (byte* stringArgTwoPtr = stringArgTwoBytes)
                                          {
                                              return TestFunction(argOne, stringArgPtr, stringArgTwoPtr);
                                          }
                                      }
                                  }
                                  public int TestFunction(int argOne, ReadOnlySpan<byte> stringArg, ReadOnlySpan<byte> stringArgTwo)
                                  {
                                      fixed (byte* stringArgPtr = stringArg)
                                      {
                                          fixed (byte* stringArgTwoPtr = stringArgTwo)
                                          {
                                              return TestFunction(argOne, stringArgPtr, stringArgTwoPtr);
                                          }
                                      }
                                  }
                              }
                              """;

        await VerifyIG.VerifyGeneratorAsync(
            code,
            ("TestStruct.InteropGenerator.g.cs", result));
    }

    [Fact]
    public async Task GenerateStringOverloadsWithIgnoredParam() {
        const string code = """
                            [global::System.Runtime.InteropServices.StructLayout(global::System.Runtime.InteropServices.LayoutKind.Explicit)]
                            [GenerateInterop]
                            public unsafe partial struct TestStruct
                            {
                                [GenerateStringOverloads]
                                public int TestFunction(int argOne, byte* stringArg, [StringIgnore] byte* notStringArg) { return 0; }
                            }
                            """;

        const string result = """
                              // <auto-generated/>
                              unsafe partial struct TestStruct
                              {
                                  public int TestFunction(int argOne, string stringArg, byte* notStringArg)
                                  {
                                      int stringArgUTF8StrLen = global::System.Text.Encoding.UTF8.GetByteCount(stringArg);
                                      Span<byte> stringArgBytes = stringArgUTF8StrLen <= 512 ? stackalloc byte[stringArgUTF8StrLen + 1] : new byte[stringArgUTF8StrLen + 1];
                                      global::System.Text.Encoding.UTF8.GetBytes(stringArg, stringArgBytes);
                                      stringArgBytes[stringArgUTF8StrLen] = 0;
                                      fixed (byte* stringArgPtr = stringArgBytes)
                                      {
                                          return TestFunction(argOne, stringArgPtr, notStringArg);
                                      }
                                  }
                                  public int TestFunction(int argOne, ReadOnlySpan<byte> stringArg, byte* notStringArg)
                                  {
                                      fixed (byte* stringArgPtr = stringArg)
                                      {
                                          return TestFunction(argOne, stringArgPtr, notStringArg);
                                      }
                                  }
                              }
                              """;

        await VerifyIG.VerifyGeneratorAsync(
            code,
            ("TestStruct.InteropGenerator.g.cs", result));
    }

    [Fact]
    public async Task GenerateStringOverloadsPartialFunction() {
        const string code = """
                            [GenerateInterop]
                            public unsafe partial struct TestStruct
                            {
                                [GenerateStringOverloads]
                                [MemberFunction("AA BB CC DD ?? ?? ?? ?? AA BB ?? DD")]
                                public partial int TestFunction(int argOne, byte * stringArg);
                            }
                            """;

        const string result = """
                              // <auto-generated/>
                              unsafe partial struct TestStruct
                              {
                                  public static class Addresses
                                  {
                                      public static readonly global::InteropGenerator.Runtime.Address TestFunction = new global::InteropGenerator.Runtime.Address("TestStruct.TestFunction", "AA BB CC DD ?? ?? ?? ?? AA BB ?? DD ?? ?? ?? ??", new byte[] {}, new ulong[] {0x00000000DDCCBBAA, 0x00000000DD00BBAA}, new ulong[] {0x00000000FFFFFFFF, 0x00000000FF00FFFF}, 0);
                                  }
                                  public static partial class Delegates
                                  {
                                      public delegate int TestFunction(TestStruct* thisPtr, int argOne, byte* stringArg);
                                  }
                                  public unsafe static class MemberFunctionPointers
                                  {
                                      public static delegate* unmanaged <TestStruct*, int, byte*, int> TestFunction => (delegate* unmanaged <TestStruct*, int, byte*, int>) TestStruct.Addresses.TestFunction.Value;
                                  }
                                  public partial int TestFunction(int argOne, byte* stringArg)
                                  {
                                      if (MemberFunctionPointers.TestFunction is null)
                                      {
                                          InteropGenerator.Runtime.ThrowHelper.ThrowNullAddress("TestStruct.TestFunction", "AA BB CC DD ?? ?? ?? ?? AA BB ?? DD");
                                      }
                                      return MemberFunctionPointers.TestFunction((TestStruct*)global::System.Runtime.CompilerServices.Unsafe.AsPointer(ref this), argOne, stringArg);
                                  }
                                  public int TestFunction(int argOne, string stringArg)
                                  {
                                      int stringArgUTF8StrLen = global::System.Text.Encoding.UTF8.GetByteCount(stringArg);
                                      Span<byte> stringArgBytes = stringArgUTF8StrLen <= 512 ? stackalloc byte[stringArgUTF8StrLen + 1] : new byte[stringArgUTF8StrLen + 1];
                                      global::System.Text.Encoding.UTF8.GetBytes(stringArg, stringArgBytes);
                                      stringArgBytes[stringArgUTF8StrLen] = 0;
                                      fixed (byte* stringArgPtr = stringArgBytes)
                                      {
                                          return TestFunction(argOne, stringArgPtr);
                                      }
                                  }
                                  public int TestFunction(int argOne, ReadOnlySpan<byte> stringArg)
                                  {
                                      fixed (byte* stringArgPtr = stringArg)
                                      {
                                          return TestFunction(argOne, stringArgPtr);
                                      }
                                  }
                              }
                              """;

        await VerifyIG.VerifyGeneratorAsync(
            code,
            ("TestStruct.InteropGenerator.g.cs", result),
            SourceGeneration.GetInitializerSource(string.Empty, "TestStruct", ["TestFunction"]));
    }
}
