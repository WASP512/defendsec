package control

import (
	"context"
	"net/http"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"defendsec/internal/telemetry"
)

// UnaryTracing traces agent RPCs. Span names are the RPC method; the
// device id is not recorded, for the same reason metrics carry none.
func UnaryTracing(t *telemetry.Tracer) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if t == nil {
			return handler(ctx, req)
		}
		parent := ""
		if md, ok := metadata.FromIncomingContext(ctx); ok {
			if v := md.Get("traceparent"); len(v) > 0 {
				parent = v[0]
			}
		}
		ctx, span := t.StartRemote(ctx, parent, info.FullMethod)
		span.SetAttr("rpc.system", "grpc")
		span.SetAttr("rpc.method", info.FullMethod)
		resp, err := handler(ctx, req)
		span.SetAttr("rpc.grpc.status_code", int(status.Code(err)))
		span.SetError(err)
		span.End()
		return resp, err
	}
}

// HTTPTracing traces admin API requests, continuing a caller's traceparent.
func HTTPTracing(t *telemetry.Tracer, next http.Handler) http.Handler {
	if t == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, span := t.StartRemote(r.Context(), r.Header.Get("traceparent"), r.Method+" "+r.URL.Path)
		span.SetAttr("http.request.method", r.Method)
		span.SetAttr("url.path", r.URL.Path)
		sw := &statusWriter{ResponseWriter: w, code: http.StatusOK}
		next.ServeHTTP(sw, r.WithContext(ctx))
		span.SetAttr("http.response.status_code", sw.code)
		if sw.code >= 500 {
			span.SetError(http.ErrAbortHandler)
		}
		span.End()
	})
}
