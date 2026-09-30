package metrics

import (
	"strings"
	"testing"
)

func TestExposition(t *testing.T) {
	r := NewRegistry()
	c := r.NewCounterVec("defendsec_test_total", "Things counted.\nSecond line.", "kind")
	c.Inc("a")
	c.Add(2, `we"ird\`)
	c.Inc("a", "extra") // wrong arity is ignored, not a panic
	h := r.NewHistogramVec("defendsec_test_seconds", "Latency.", []float64{0.1, 1}, "op")
	h.Observe(0.05, "x")
	h.Observe(0.5, "x")
	h.Observe(5, "x")
	r.NewGaugeFunc("defendsec_test_gauge", "A gauge.", []string{"p"}, func() []Sample {
		return []Sample{{Labels: []string{"linux"}, Value: 3}}
	})
	var b strings.Builder
	r.Write(&b)
	got := b.String()
	for _, want := range []string{
		"# HELP defendsec_test_total Things counted.\\nSecond line.\n# TYPE defendsec_test_total counter\n",
		`defendsec_test_total{kind="a"} 1`,
		`defendsec_test_total{kind="we\"ird\\"} 2`,
		`defendsec_test_seconds_bucket{op="x",le="0.1"} 1`,
		`defendsec_test_seconds_bucket{op="x",le="1"} 2`,
		`defendsec_test_seconds_bucket{op="x",le="+Inf"} 3`,
		`defendsec_test_seconds_sum{op="x"} 5.55`,
		`defendsec_test_seconds_count{op="x"} 3`,
		`defendsec_test_gauge{p="linux"} 3`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

func TestRegisteringTwiceReturnsTheSameMetric(t *testing.T) {
	r := NewRegistry()
	a := r.NewCounterVec("defendsec_x_total", "x", "k")
	b := r.NewCounterVec("defendsec_x_total", "x", "k")
	if a != b {
		t.Fatal("second registration must return the first")
	}
}
