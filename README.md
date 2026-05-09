# openaiaddz
using ai [openai] on ad hacking 


# openaiad
openaiad AD enum and hacking with ai 

# BUILD 

```
go mod init openaiaddz.go
go mod tidy
go build -o openaiaddz openaiaddz
```


# Just OpenAI chat
```
./openaiaddz -mode openai -openai-token "sk-xxx" -query "Explain Kerberoasting"
```
# Just AD recon (anonymous bind)
```
./openaiad -mode ad-recon -ldap "ldap://dc.target.local:389"
```
# AD recon with authentication
```
./openaiaddz -mode ad-recon \
  -ldap "ldap://dc.target.local:389" \
  -bind-user "cn=readonly,dc=target,dc=local" \
  -bind-pass "password123" \
  -base-dn "dc=target,dc=local"
```
# Run both: AD recon + OpenAI analysis
```
./openaiaddz -mode all \
  -openai-token "sk-xxx" \
  -ldap "ldap://dc.target.local:389" \
  -bind-user "cn=user,dc=target,dc=local" \
  -bind-pass "pass"

  ```
