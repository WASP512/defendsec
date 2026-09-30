variables {
  server        = "defendsec.example.internal"
  enroll_secret = "s3cr3t-value"
}

run "linux_without_ca" {
  command = plan
  assert {
    condition     = strcontains(output.user_data, "--enroll-secret 's3cr3t-value'") && strcontains(output.user_data, "https://defendsec.example.internal:47261/downloads/install-agent.sh")
    error_message = "linux script is missing enrollment arguments"
  }
  assert {
    condition     = !strcontains(output.user_data, "--insecure") && !strcontains(output.user_data, "--download-ca")
    error_message = "no CA was given, so none is passed, and verification is never skipped"
  }
}

run "linux_with_ca" {
  command = plan
  variables {
    console_ca_pem = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"
  }
  assert {
    condition     = strcontains(output.user_data, "--download-ca \"$work/console.crt\"") && strcontains(output.user_data, "cacert=(--cacert")
    error_message = "the CA must verify both the installer download and the agent download"
  }
}

run "windows" {
  command = plan
  variables {
    platform = "windows"
  }
  assert {
    condition     = startswith(output.user_data, "<powershell>") && strcontains(output.user_data, "ENROLL_SECRET=s3cr3t-value")
    error_message = "windows user data must be a <powershell> block installing the MSI"
  }
}

run "rejects_bad_platform" {
  command = plan
  variables {
    platform = "plan9"
  }
  expect_failures = [var.platform]
}
