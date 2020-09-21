# sigma-go ![Build Status](https://github.com/bradleyjkemp/sigma-go/.github/workflows/go.yml/badge.svg) [![GitHub release](https://img.shields.io/github/release/bradleyjkemp/sigma-go.svg)](https://github.com/bradleyjkemp/sigma-go/releases/latest)
<img src=".github/mascot.png" alt="Mascot" width="150" align="right">

A Go implementation and parser of [Sigma rules](https://github.com/Neo23x0/sigma). Useful for building your own detection pipelines.

⚠️ This library is under development and an implementation of a draft specification. Test this well if you're using it for anything important.

## Usage

This library is designed for you to build your own alert systems.
It exposes the ability to check whether a rule matches a given event but not much else.
It's up to you to use this building block in your own detection pipeline.

A basic usage of this library might look like this:
```go
// You can load/create rules dynamically or use sigmac to load Sigma rule files
var rule, _ = sigma.ParseRule(contents)

// Rules need to be wrapped in an evaluator.
// This is also where (if needed) you provide functions implementing the count, max, etc. aggregation functions
e := sigma.Evaluator(rule, options...)

// Get a stream of events from somewhere e.g. audit logs
for event := range events {
    if e.Matches(ctx, event) {
        // Raise your alert here
        newAlert(rule.ID, rule.Description, ...)
    }
}
```

### Aggregation functions

If your Sigma rules make use of the count, max, min, or any other aggregation function in your conditions then you'll need some extra setup.

When creating an evaluator, you can pass in implementations of each of the aggregation functions:
```go
sigma.Evaluator(rule, sigma.CountFunc(countImplementation), sigma.MaxFunc(maxImplementation))
```

This repo includes some toy implementations in the `aggregators` package but for production use cases you'll need to supply your own.


### `sigmac`

To make managing rules easy, this repo includes a tool to "compile" directories of rules into Go packages.

```
./malware/rule_one.yaml
./malware/another_rule.yaml
```

Running the `sigmac` tool in this directory will generate a `sigma.go` file:
```bash
> go run github.com/bradleyjkemp/sigma-go/sigmac ./malware
```

The `sigma.go` file contains a map of parsed Sigma rules by their ID that you can iterate over when matching events.

```go
for id, rule := range malware.Rules {
    if sigma.Evaluator(rule).Matches(event) {
        fmt.Println("event %v matched rule %s!", event, id)
    }
}
```