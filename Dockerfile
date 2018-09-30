FROM microsoft/dotnet:2.1.402-sdk as builder 

#copy webapi project and publish to /artifacts/app
ADD . /src/
RUN dotnet publish ./src/demo.csproj -o /artifacts/app -c Release --runtime debian.9-x64

FROM microsoft/dotnet:2.1.4-aspnetcore-runtime

ENV ASPNETCORE_ENVIRONMENT Development
ENV ASPNETCORE_URLS http://+:80
WORKDIR /app
#copy published app to /app folder
COPY --from=builder /artifacts/app .
EXPOSE 80

ENTRYPOINT ["dotnet", "demo.dll"]