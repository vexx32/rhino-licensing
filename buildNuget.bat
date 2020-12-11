REM OLD WAY Tools\nuget pack Rhino.Licensing\Rhino.Licensing.csproj -Prop Configuration=Release -OutputDirectory build -Symbols -Build
REM msbuild must be from >15.4 build tools
REM EG "C:\Program Files (x86)\Microsoft Visual Studio\2017\Professional\MSBuild\15.0\Bin\amd64\msbuild"
"C:\Program Files (x86)\Microsoft Visual Studio\2017\Professional\MSBuild\15.0\Bin\amd64\msbuild" .\Rhino.Licensing\Rhino.Licensing.csproj /t:pack /p:Configuration=Release /p:Platform="Any CPU"