# snpreport
Golang module for decoding and verifying AMD SEV SNP attestation reports for golang projects.

You, yes! You can authenticate and parse AMD SEV SNP attestation reports!

You probably have questions.

Like, what is AMD SEV SNP? Here's some info: TODO

Also, what are AMD SEV SNP attestation reports? Here's some more info: TODO

and here's some more: TODO

Now that you've read every word on those links (yeah, right), here's how to use this module.

When you receive an attestation report (as `documentData []byte`), call:
```

report, err := AuthenticateReport(documentData, publicKey)
if err != nil {
  // either the signature verification on the report data failed
  // or the documentData was malformed, or the publicKey had a problem,
  // or any number of things went wrong.
}
```

This crate is intended for use from golang projects. If you need support in another language, that is mostly left up to the reader.