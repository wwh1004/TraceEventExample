@echo off
dotnet publish TraceEventExample -r win-x64 -c Release ^
  -p:Platform=x64 ^
  -p:PublishDir=..\bin\ ^
  -p:TargetFramework=net8.0 ^
  -p:RuntimeIdentifier=win-x64 ^
  -p:SelfContained=true ^
  -p:PublishSingleFile=true
