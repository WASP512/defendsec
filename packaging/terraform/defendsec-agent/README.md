# Terraform: DefendSec agent user data

Renders the first-boot script that installs and enrolls the DefendSec agent
on a new instance. It creates no resources, so it works with any provider
that takes user data.

```hcl
module "defendsec" {
  source         = "github.com/WASP512/defendsec//packaging/terraform/defendsec-agent"
  server         = "defendsec.example.internal"
  enroll_secret  = var.defendsec_enroll_secret   # sensitive
  console_ca_pem = file("console.crt")           # when the console is self-signed
  platform       = "linux"                       # or "windows" (installs the MSI)
}

resource "aws_instance" "web" {
  # ...
  user_data = module.defendsec.user_data
}
```

The output is sensitive: it contains the enroll secret, and so does your
Terraform state. Rotate the secret on the Enroll page once provisioning is
done, if state is shared more widely than the secret should be. Enrolled
agents are unaffected by rotation.

Tested with `terraform test` (tests/render.tftest.hcl).
