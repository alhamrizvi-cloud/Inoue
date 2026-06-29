---
name: Bug report
title: "[BUG] "
description: Create a report to help us improve Inoue
labels: bug
body:
  - type: markdown
    attributes:
      value: Thanks for taking the time to fill out this bug report!
  - type: textarea
    id: description
    attributes:
      label: Describe the bug
      placeholder: What happened?
    validations:
      required: true
  - type: textarea
    id: steps
    attributes:
      label: Steps to reproduce
      placeholder: Tell us how to reproduce the issue.
    validations:
      required: true
  - type: textarea
    id: expected
    attributes:
      label: Expected behavior
      placeholder: What did you expect to happen?
    validations:
      required: true
