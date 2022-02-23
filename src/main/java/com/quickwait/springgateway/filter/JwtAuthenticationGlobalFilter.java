package com.quickwait.springgateway.filter;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.function.Predicate;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import com.quickwait.springgateway.exception.JwtTokenMalformedException;
import com.quickwait.springgateway.exception.JwtTokenMissingException;
import com.quickwait.springgateway.util.JwtUtil;

import io.jsonwebtoken.Claims;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Component
public class JwtAuthenticationGlobalFilter implements GlobalFilter {

	@Autowired
	private JwtUtil jwtUtil;
	
	@Value("#{'${quickWait.non-authenticated-endpoints}'.split(',')}")
	private List<String> nonAuthenticatedEndpoints;
	
	@Override
	public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
		ServerHttpRequest request = (ServerHttpRequest) exchange.getRequest();

		Predicate<ServerHttpRequest> isApiSecured = 
					req -> nonAuthenticatedEndpoints.stream()
							.noneMatch(uri -> req.getURI().getPath().contains(uri));

		if (isApiSecured.test(request)) {
			if (!request.getHeaders().containsKey("Authorization")) {
				ServerHttpResponse response = exchange.getResponse();
				response.setStatusCode(HttpStatus.UNAUTHORIZED);
				
				return response.setComplete();
			}

			final String token = request.getHeaders().getOrEmpty("Authorization").get(0).replace("Bearer ", "");

			try {
				jwtUtil.validateToken(token);
				
			} catch (JwtTokenMalformedException | JwtTokenMissingException e) {
				DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(e.getMessage().getBytes(StandardCharsets.UTF_8));
				exchange.getResponse().setStatusCode(HttpStatus.BAD_REQUEST);
				
				return exchange.getResponse().writeWith(Flux.just(buffer));
			}

			Claims claims = jwtUtil.getClaims(token);
			exchange.getRequest().mutate().header("username", String.valueOf(claims.get("username"))).build();
		}
		
		return chain.filter(exchange);
	}
	
}
