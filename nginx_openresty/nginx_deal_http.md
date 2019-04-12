在 Nginx 的初始化启动过程中，worker 工作进程会调用事件模块的ngx_event_process_init 方法为每个监听套接字ngx_listening_t 分配一个 ngx_connection_t 连接，并设置该连接上读事件的回调方法handler 为ngx_event_accept，同时将读事件挂载到epoll 事件机制中等待监听套接字连接上的可读事件发生，到此，Nginx 就可以接收并处理来自客户端的请求。当监听套接字连接上的可读事件发生时，即该连接上有来自客户端发出的连接请求，则会启动读事件的handler 回调方法ngx_event_accept，在ngx_event_accept 方法中调用accept() 函数接收来自客户端的连接请求，成功建立连接之后，ngx_event_accept 函数调用监听套接字上的handler 回调方法ls->handler(c)（该回调方法就是ngx_http_init_connection）。因此，成功建立连接之后由ngx_http_init_connection 方法开始处理该连接上的请求数据。
接收 HTTP 请求报文

在接收 HTTP 请求之前，首先会初始化已成功建立的连接；ngx_http_init_connection 函数的功能是设置读、写事件的回调方法，而实际上写事件的回调方法并不进行任何操作，读事件的回调方法是对HTTP 请求进程初始化工作。
ngx_http_init_connection 函数的执行流程：
设置当前连接上写事件的回调方法 handler 为 ngx_http_empty_handler（实际上该方法不进行任何操作）；
设置当前连接上读事件的回调方法 handler 为 ngx_http_wait_request_handler；
检查当前连接上读事件是否准备就绪（即 ready 标志位为1）：
若读事件 ready 标志位为1，表示当前连接上有可读的TCP 流，则执行读事件的回调方法ngx_http_wait_request_handler；
若读事件 ready 标志位为0，表示当前连接上没有可读的TCP 流，则将读事件添加到定时器事件机制中（监控可读事件是否超时），同时将读事件注册到epoll 事件机制中，等待可读事件的发生；
函数 ngx_http_init_connection 在文件src/http/ngx_http_request.c 中定义如下：
```
void
ngx_http_init_connection(ngx_connection_t *c)
{
    ngx_uint_t              i;
    ngx_event_t            *rev;
    struct sockaddr_in     *sin;
    ngx_http_port_t        *port;
    ngx_http_in_addr_t     *addr;
    ngx_http_log_ctx_t     *ctx;
    ngx_http_connection_t  *hc;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6    *sin6;
    ngx_http_in6_addr_t    *addr6;
#endif

    /* 分配http连接ngx_http_connection_t结构体空间 */
    hc = ngx_pcalloc(c->pool, sizeof(ngx_http_connection_t));
    if (hc == NULL) {
        ngx_http_close_connection(c);
        return;
    }

    c->data = hc;

    /* find the server configuration for the address:port */

    port = c->listening->servers;

    if (port->naddrs > 1) {

        /*
         * there are several addresses on this port and one of them
         * is an "*:port" wildcard so getsockname() in ngx_http_server_addr()
         * is required to determine a server address
         */

        if (ngx_connection_local_sockaddr(c, NULL, 0) != NGX_OK) {
            ngx_http_close_connection(c);
            return;
        }

        switch (c->local_sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
        ...
#endif

        default: /* AF_INET */
            sin = (struct sockaddr_in *) c->local_sockaddr;

            addr = port->addrs;

            /* the last address is "*" */

            for (i = 0; i < port->naddrs - 1; i++) {
                if (addr[i].addr == sin->sin_addr.s_addr) {
                    break;
                }
            }

            hc->addr_conf = &addr[i].conf;

            break;
        }

    } else {

        switch (c->local_sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
        ...
#endif

        default: /* AF_INET */
            addr = port->addrs;
            hc->addr_conf = &addr[0].conf;
            break;
        }
    }

    /* the default server configuration for the address:port */
    hc->conf_ctx = hc->addr_conf->default_server->ctx;

    ctx = ngx_palloc(c->pool, sizeof(ngx_http_log_ctx_t));
    if (ctx == NULL) {
        ngx_http_close_connection(c);
        return;
    }

    ctx->connection = c;
    ctx->request = NULL;
    ctx->current_request = NULL;

    /* 设置当前连接的日志属性 */
    c->log->connection = c->number;
    c->log->handler = ngx_http_log_error;
    c->log->data = ctx;
    c->log->action = "waiting for request";

    c->log_error = NGX_ERROR_INFO;

    /* 设置当前连接读、写事件的handler处理方法 */
    rev = c->read;
    /* 设置当前连接读事件的处理方法handler为ngx_http_wait_request_handler */
    rev->handler = ngx_http_wait_request_handler;
    /*
     * 设置当前连接写事件的处理方法handler为ngx_http_empty_handler，
     * 该方法不执行任何实际操作，只记录日志；
     * 因为处理请求的过程不需要write方法；
     */
    c->write->handler = ngx_http_empty_handler;

#if (NGX_HTTP_SPDY)
   ...
#endif

#if (NGX_HTTP_SSL)
    ...
#endif

    if (hc->addr_conf->proxy_protocol) {
        hc->proxy_protocol = 1;
        c->log->action = "reading PROXY protocol";
    }

    /* 若读事件准备就绪，则判断是否使用同步锁，
     * 根据同步锁情况判断决定是否立即处理该事件；
     */
    if (rev->ready) {
        /* the deferred accept(), rtsig, aio, iocp */

        /*
         * 若使用了同步锁ngx_use_accept_mutex，
         * 则将该读事件添加到待处理事件队列ngx_post_event中，
         * 直到退出锁时，才处理该读事件；
         */
        if (ngx_use_accept_mutex) {
            ngx_post_event(rev, &ngx_posted_events);
            return;
        }

        /* 若没有使用同步锁，则直接处理该读事件；
         * 读事件的处理函数handler为ngx_http_wait_request_handler；
         */
        rev->handler(rev);
        return;
    }

    /*
     * 若当前连接的读事件未准备就绪，
     * 则将其添加到定时器事件机制，并注册到epoll事件机制中；
     */

    /* 将当前连接的读事件添加到定时器机制中 */
    ngx_add_timer(rev, c->listening->post_accept_timeout);
    ngx_reusable_connection(c, 1);

    /* 将当前连接的读事件注册到epoll事件机制中 */
    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        ngx_http_close_connection(c);
        return;
    }
}
```
当连接上第一次出现可读事件时，会调用 ngx_http_wait_request_handler 函数，该函数的功能是初始化HTTP 请求，但是它并不会在成功建立连接之后就立刻初始化请求，而是在当前连接所对应的套接字缓冲区上确定接收到来自客户端的实际请求数据时才真正进行初始化工作，这样做可以减少不必要的内存消耗（若当成功建立连接之后，客户端并不进行实际数据通信，而此时Nginx 却因为初始化工作分配内存）。
ngx_http_wait_request_handler 函数的执行流程：
首先判断当前读事件是否超时（即读事件的 timedout 标志位是否为1）：
若 timedout 标志位为1，表示当前读事件已经超时，则调用ngx_http_close_connection 方法关闭当前连接，return 从当前函数返回；
若 timedout 标志位为0，表示当前读事件还未超时，则继续检查当前连接的close标志位；
若当前连接的 close 标志位为1，表示当前连接要关闭，则调用ngx_http_close_connection 方法关闭当前连接，return 从当前函数返回；
若当前连接的 close 标志位为0，表示不需要关闭当前连接，进而调用recv() 函数尝试从当前连接所对应的套接字缓冲区中接收数据，这个步骤是为了确定客户端是否真正的发送请求数据，以免因为客户端不发送实际请求数据，出现初始化请求而导致内存被消耗。根据所读取的数据情况n 来判断是否要真正进行初始化请求工作：
若 n = NGX_AGAIN，表示客户端发起连接请求，但是暂时还没发送实际的数据，则将当前连接上的读事件添加到定时器机制中，同时将读事件注册到epoll 事件机制中，return 从当前函数返回；
若 n = NGX_ERROR，表示当前连接出错，则直接调用ngx_http_close_connection 关闭当前连接，return 从当前函数返回；
若 n = 0，表示客户端已经主动关闭当前连接，所有服务器端调用ngx_http_close_connection 关闭当前连接，return 从当前函数返回；
若 n 大于 0，表示读取到实际的请求数据，因此决定开始初始化当前请求，继续往下执行；
调用 ngx_http_create_request 方法构造ngx_http_request_t 请求结构体，并设置到当前连接的data 成员；
设置当前读事件的回调方法为 ngx_http_process_request_line，并执行该回调方法开始接收并解析请求行；
函数 ngx_http_wait_request_handler 在文件src/http/ngx_http_request.c 中定义如下：
```
/* 处理连接的可读事件 */
static void
ngx_http_wait_request_handler(ngx_event_t *rev)
{
    u_char                    *p;
    size_t                     size;
    ssize_t                    n;
    ngx_buf_t                 *b;
    ngx_connection_t          *c;
    ngx_http_connection_t     *hc;
    ngx_http_core_srv_conf_t  *cscf;

    /* 获取读事件所对应的连接ngx_connection_t 对象 */
    c = rev->data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http wait request handler");

    /* 若当前读事件超时，则记录错误日志，关闭所对应的连接并退出 */
    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
        ngx_http_close_connection(c);
        return;
    }

    /* 若当前读事件所对应的连接设置关闭连接标志位，则关闭该链接 */
    if (c->close) {
        ngx_http_close_connection(c);
        return;
    }

    /* 若当前读事件不超时，且其所对应的连接不设置close标志位，则继续指向以下语句 */

    hc = c->data;
    /* 获取当前读事件请求的相关配置项结构 */
    cscf = ngx_http_get_module_srv_conf(hc->conf_ctx, ngx_http_core_module);

    size = cscf->client_header_buffer_size;

    /* 以下内容是接收缓冲区的操作 */
    b = c->buffer;

    /* 若当前连接的接收缓冲区不存在，则创建该接收缓冲区 */
    if (b == NULL) {
        b = ngx_create_temp_buf(c->pool, size);
        if (b == NULL) {
            ngx_http_close_connection(c);
            return;
        }

        c->buffer = b;

    } else if (b->start == NULL) {
        /* 若当前接收缓冲区存在，但是为空，则为其分配内存 */

        b->start = ngx_palloc(c->pool, size);
        if (b->start == NULL) {
            ngx_http_close_connection(c);
            return;
        }

        /* 初始化接收缓冲区各成员指针 */
        b->pos = b->start;
        b->last = b->start;
        b->end = b->last + size;
    }

    /* 在当前连接上开始接收HTTP请求数据 */
    n = c->recv(c, b->last, size);

    if (n == NGX_AGAIN) {

        if (!rev->timer_set) {
            ngx_add_timer(rev, c->listening->post_accept_timeout);
            ngx_reusable_connection(c, 1);
        }

        if (ngx_handle_read_event(rev, 0) != NGX_OK) {
            ngx_http_close_connection(c);
            return;
        }

        /*
         * We are trying to not hold c->buffer's memory for an idle connection.
         */

        if (ngx_pfree(c->pool, b->start) == NGX_OK) {
            b->start = NULL;
        }

        return;
    }

    if (n == NGX_ERROR) {
        ngx_http_close_connection(c);
        return;
    }

    if (n == 0) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "client closed connection");
        ngx_http_close_connection(c);
        return;
    }

    /* 若接收HTTP请求数据成功，则调整接收缓冲区成员指针 */
    b->last += n;

    if (hc->proxy_protocol) {
        hc->proxy_protocol = 0;

        p = ngx_proxy_protocol_parse(c, b->pos, b->last);

        if (p == NULL) {
            ngx_http_close_connection(c);
            return;
        }

        b->pos = p;

        if (b->pos == b->last) {
            c->log->action = "waiting for request";
            b->pos = b->start;
            b->last = b->start;
            ngx_post_event(rev, &ngx_posted_events);
            return;
        }
    }

    c->log->action = "reading client request line";

    ngx_reusable_connection(c, 0);

    /* 为当前连接创建一个请求结构体ngx_http_request_t */
    c->data = ngx_http_create_request(c);
    if (c->data == NULL) {
        ngx_http_close_connection(c);
        return;
    }

    /* 设置当前读事件的处理方法为ngx_http_process_request_line */
    rev->handler = ngx_http_process_request_line;
    /* 执行该读事件的处理方法ngx_http_process_request_line，接收HTTP请求行 */
    ngx_http_process_request_line(rev);
}
```
接收 HTTP 请求行

HTTP 请求的初始化完成之后会调用 ngx_http_process_request_line 方法开始接收并解析 HTTP 请求行。在 HTTP 协议中我们可以知道，请求行的长度并不是固定的，它与URI 长度相关，若当内核套接字缓冲区不能一次性完整的接收HTTP 请求行时，会多次调用ngx_http_process_request_line 方法继续接收，即ngx_http_process_request_line 方法重新作为当前连接上读事件的回调方法，必要时将读事件添加到定时器机制，注册到epoll 事件机制，直到接收并解析出完整的HTTP 请求行。
ngx_http_process_request_line 处理HTTP 请求行函数执行流程：
首先，判断当前请求是否超时，若超时（即读事件的 timedout 标志位为1），则设置当前连接的超时标志位为1（c->timedout = 1），调用ngx_http_close_request 方法关闭该请求，并return 从当前函数返回；
若当前请求未超时（读事件的 timedout 标志位为 0），调用 ngx_http_read_request_header 方法开始读取当前请求行，根据该函数的返回值n 进行以下判断：
若返回值 n = NGX_AGAIN，表示当前连接上套接字缓冲区不存在可读TCP 流，则需将当前读事件添加到定时器机制，注册到epoll 事件机制中，等待可读事件发生。return 从当前函数返回；
若返回值 n = NGX_ERROR，表示当前连接出错，则调用ngx_http_finalize_request 方法结束请求，return 从当前函数返回；
若返回值 n 大于 0，表示读取请求行成功，调用函数 ngx_http_parse_request_line 开始解析由函数ngx_http_read_request_header 读取所返回的请求行，根据函数ngx_http_parse_request_line 函数返回值rc 不同进行判断；
若返回值 rc = NGX_ERROR，表示解析请求行时出错，此时，调用ngx_http_finalize_request 方法终止该请求，并return 从当前函数返回；
若返回值 rc = NGX_AGAIN，表示没有解析到完整的请求行，即仍需接收请求行，首先根据要求调整接收缓冲区header_in 的内存空间，则继续调用函数ngx_http_read_request_header 读取请求数据进入请求行自动处理机制，直到请求行解析完毕；
若返回值 rc = NGX_OK，表示解析到完整的 HTTP 请求行，则设置请求行的成员信息（例如：方法名称、URI 参数、HTTP 版本等信息）；
若 HTTP 协议版本小于 1.0 版本，表示不需要处理 HTTP 请求头部，则直接调用函数ngx_http_process_request 处理该请求，return 从当前函数返回；
若HTTP协议版本不小于 1.0 版本，表示需要处理HTTP请求头部：
调用函数 ngx_list_init 初始化保存 HTTP 请求头部的结构体 ngx_http_request_t 中成员headers_in 链表容器（该链表缓冲区是保存所接收到的HTTP 请求数据）；
设置当前读事件的回调方法为 ngx_http_process_request_headers 方法，并调用该方法ngx_http_process_request_headers 开始处理HTTP 请求头部。return 从当前函数返回；
函数 ngx_http_process_request_line 在文件src/http/ngx_http_request.c 中定义如下：
```
/* 处理HTTP请求行 */
static void
ngx_http_process_request_line(ngx_event_t *rev)
{
    ssize_t              n;
    ngx_int_t            rc, rv;
    ngx_str_t            host;
    ngx_connection_t    *c;
    ngx_http_request_t  *r;

    /* 获取当前读事件所对应的连接 */
    c = rev->data;
    /* 获取连接中所对应的请求结构 */
    r = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, rev->log, 0,
                   "http process request line");

    /* 若当前读事件超时，则进行相应地处理，并关闭当前请求 */
    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
        c->timedout = 1;
        ngx_http_close_request(r, NGX_HTTP_REQUEST_TIME_OUT);
        return;
    }

    /* 设置NGX_AGAIN标志，表示请求行还没解析完毕 */
    rc = NGX_AGAIN;

    for ( ;; ) {

        /* 若请求行还没解析完毕，则继续解析 */
        if (rc == NGX_AGAIN) {
            /* 读取当前请求未解析的数据 */
            n = ngx_http_read_request_header(r);

            /* 若没有数据，或读取失败，则直接退出 */
            if (n == NGX_AGAIN || n == NGX_ERROR) {
                return;
            }
        }

        /* 解析接收缓冲区header_in中的请求行 */
        rc = ngx_http_parse_request_line(r, r->header_in);

        /* 若请求行解析完毕 */
        if (rc == NGX_OK) {

            /* the request line has been parsed successfully */

            /* 设置请求行的成员，请求行是ngx_str_t类型 */
            r->request_line.len = r->request_end - r->request_start;
            r->request_line.data = r->request_start;
            /* 设置请求长度，包括请求头部、请求包体 */
            r->request_length = r->header_in->pos - r->request_start;

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                           "http request line: \"%V\"", &r->request_line);

            /* 设置请求方法名称字符串 */
            r->method_name.len = r->method_end - r->request_start + 1;
            r->method_name.data = r->request_line.data;

            /* 设置HTTP请求协议 */
            if (r->http_protocol.data) {
                r->http_protocol.len = r->request_end - r->http_protocol.data;
            }

            /* 处理请求中的URI */
            if (ngx_http_process_request_uri(r) != NGX_OK) {
                return;
            }

            if (r->host_start && r->host_end) {

                host.len = r->host_end - r->host_start;
                host.data = r->host_start;

                rc = ngx_http_validate_host(&host, r->pool, 0);

                if (rc == NGX_DECLINED) {
                    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                                  "client sent invalid host in request line");
                    ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
                    return;
                }

                if (rc == NGX_ERROR) {
                    ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                    return;
                }

                if (ngx_http_set_virtual_server(r, &host) == NGX_ERROR) {
                    return;
                }

                r->headers_in.server = host;
            }

            /* 设置请求协议版本 */
            if (r->http_version < NGX_HTTP_VERSION_10) {

                if (r->headers_in.server.len == 0
                    && ngx_http_set_virtual_server(r, &r->headers_in.server)
                       == NGX_ERROR)
                {
                    return;
                }

                /* 若HTTP版本小于1.0版本，则表示不需要接收HTTP请求头部，则直接处理请求 */
                ngx_http_process_request(r);
                return;
            }

            /* 初始化链表容器，为接收HTTP请求头部做准备 */
            if (ngx_list_init(&r->headers_in.headers, r->pool, 20,
                              sizeof(ngx_table_elt_t))
                != NGX_OK)
            {
                ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }

            c->log->action = "reading client request headers";

            /* 若请求行解析完毕，则接下来处理请求头部 */

            /* 设置连接读事件的回调方法 */
            rev->handler = ngx_http_process_request_headers;
            /* 开始处理HTTP请求头部 */
            ngx_http_process_request_headers(rev);

            return;
        }

        /* 解析请求行出错 */
        if (rc != NGX_AGAIN) {

            /* there was error while a request line parsing */

            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                          ngx_http_client_errors[rc - NGX_HTTP_CLIENT_ERROR]);
            ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
            return;
        }

        /* NGX_AGAIN: a request line parsing is still incomplete */

        /* 请求行仍然未解析完毕，则继续读取请求数据 */

        /* 若当前接收缓冲区内存不够，则分配更大的内存空间 */
        if (r->header_in->pos == r->header_in->end) {

            rv = ngx_http_alloc_large_header_buffer(r, 1);

            if (rv == NGX_ERROR) {
                ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }

            if (rv == NGX_DECLINED) {
                r->request_line.len = r->header_in->end - r->request_start;
                r->request_line.data = r->request_start;

                ngx_log_error(NGX_LOG_INFO, c->log, 0,
                              "client sent too long URI");
                ngx_http_finalize_request(r, NGX_HTTP_REQUEST_URI_TOO_LARGE);
                return;
            }
        }
    }
}
```
在接收并解析请求行的过程中会调用 ngx_http_read_request_header 读取请求数据，我们看下该函数是如何读取到请求数据的。
ngx_http_read_request_header 读取请求数据函数执行流程：
检测当前请求的接收缓冲区 header_in 是否有数据，若有直接返回该数据n；
若接收缓冲区 header_in 没有数据，检查当前读事件是否准备就绪（即判断ready 标志位是否为0 ）：
若当前读事件未准备就绪（即当前读事件 ready 标志位为0），则设置返回值n= NGX_AGAIN；
若当前读事件已经准备就绪（即 ready 标志位为 1），则调用 recv() 方法从当前连接套接字中读取数据并保存到接收缓冲区header_in 中，并设置n 为recv()方法所读取的数据的返回值；
下面根据 n 的取值执行不同的操作：
若 n = NGX_AGAIN（此时，n 的值可能当前事件未准备就绪而设置的NGX_AGAIN，也可能是recv()方法返回的NGX_AGAIN 值，但是只能是其中一种情况），将当前读事件添加到定时器事件机制中， 将当前读事件注册到epoll 事件机制中，等待事件可读，n 从当前函数返回；
若 n = 0 或 n = ERROR，则调用 ngx_http_finalize_request 结束请求，并返回NGX_ERROR 退出当前函数；
函数 ngx_http_read_request_header 在文件src/http/ngx_http_request.c 中定义如下：
```
static ssize_t
ngx_http_read_request_header(ngx_http_request_t *r)
{
    ssize_t                    n;
    ngx_event_t               *rev;
    ngx_connection_t          *c;
    ngx_http_core_srv_conf_t  *cscf;

    /* 获取当前请求所对应的连接 */
    c = r->connection;
    /* 获取当前连接的读事件 */
    rev = c->read;

    /* 获取当前请求接收缓冲区的数据，header_in 是ngx_buf_t类型 */
    n = r->header_in->last - r->header_in->pos;

    /* 若接收缓冲区有数据，则直接返回该数据 */
    if (n > 0) {
        return n;
    }

    /* 若当前接收缓冲区没有数据，首先判断当前读事件是否准备就绪 */
    if (rev->ready) {
        /* 若当前读事件已准备就绪，则从其所对应的连接套接字读取数据，并保存到接收缓冲区中 */
        n = c->recv(c, r->header_in->last,
                    r->header_in->end - r->header_in->last);
    } else {
        /* 若接收缓冲区没有数据，且读事件未准备就绪，则设置为NGX_AGAIN */
        n = NGX_AGAIN;
    }

    /* 若接收缓冲区没有数据，且读事件未准备就绪，则设置为NGX_AGAIN */
    /* 将当前读事件添加到定时器机制；
     * 将当前读事件注册到epoll事件机制；
     */
    if (n == NGX_AGAIN) {
        if (!rev->timer_set) {
            cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);
            /* 将当前读事件添加到定时器机制中 */
            ngx_add_timer(rev, cscf->client_header_timeout);
        }

        /* 将当前读事件注册到epoll事件机制中 */
        if (ngx_handle_read_event(rev, 0) != NGX_OK) {
            ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return NGX_ERROR;
        }

        return NGX_AGAIN;
    }

    if (n == 0) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "client prematurely closed connection");
    }

    if (n == 0 || n == NGX_ERROR) {
        c->error = 1;
        c->log->action = "reading client request headers";

        ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
        return NGX_ERROR;
    }

    r->header_in->last += n;

    return n;
}
```
接收 HTTP 请求头部

前面已经成功接收并解析了 HTTP 请求行，这里根据读事件的回调方法ngx_http_process_request_headers 开始接收并解析HTTP 请求头部，但是并不一定能够一次性接收到完整的HTTP 请求头部，因此，可以多次调用该函数，直到接收到完整的HTTP 请求头部。
ngx_http_process_request_headers 处理HTTP 请求头部函数执行流程：
首先，判断当前请求读事件是否超时，若超时（即读事件的 timedout 标志位为1），则设置当前连接超时标志位为1（c->timedout = 1），并调用ngx_http_close_request 方法关闭该请求，并return 从当前函数返回；
若当前请求读事件未超时（即读事件的 timedout 标志位为0），检查接收HTTP 请求头部的header_in 缓冲区是否有剩余内存空间，若没有剩余的内存空间，则调用ngx_http_alloc_large_header_buffer 方法分配更大的缓冲区。若有剩余的内存，则无需再分配内存空间。
调用 ngx_http_read_request_header 方法开始读取当前请求头部保存到header_in 缓冲区中，根据该函数的返回值 n 进行以下判断：
若返回值 n = NGX_AGAIN，表示当前连接上套接字缓冲区不存在可读TCP 流，则需将当前读事件添加到定时器机制，注册到epoll 事件机制中，等待可读事件发生。return 从当前函数返回；
若返回值 n = NGX_ERROR，表示当前连接出错，则调用ngx_http_finalize_request 方法结束请求，return 从当前函数返回；
若返回值 n 大于 0，表示读取请求头部成功，调用函数 ngx_http_parse_request_line 开始解析由函数ngx_http_read_request_header 读取所返回的请求头部，根据函数ngx_http_parse_request_line 函数返回值rc不同进行判断；
若返回值 rc = NGX_ERROR，表示解析请求行时出错，此时，调用ngx_http_finalize_request 方法终止该请求，并return 从当前函数返回；
若返回值 rc = NGX_AGAIN，表示没有解析到完整一行的请求头部，仍需继续接收TCP 字符流才能够是完整一行的请求头部，则continue 继续调用函数ngx_http_read_request_header 和ngx_http_parse_request_line 方法读取并解析下一行请求头部，直到全部请求头部解析完毕；
若返回值 rc = NGX_OK，表示解析出一行 HTTP 请求头部（注意：一行请求头部只是整个请求头部的一部分），判断当前解析出来的一行请求头部是否合法，若非法，则忽略当前一行请求头部，继续读取并解析下一行请求头部。若合法，则调用ngx_list_push 方法将该行请求头部设置到当前请求ngx_http_request_t 结构体 header_in 缓冲区成员的headers 链表中，设置请求头部名称的hash 值，并continue 继续调用函数ngx_http_read_request_header 和ngx_http_parse_request_line 方法读取并解析下一行请求头部，直到全部请求头部解析完毕；
若返回值 rc = NGX_HTTP_PARSE_HEADER_DONE，则表示已经读取并解析出全部请求头部，此时，调用ngx_http_process_request 方法开始处理请求，return 从当前函数返回；
函数 ngx_http_process_request_headers 在文件src/http/ngx_http_request.c 中定义如下：
```
/* 处理HTTP请求头部 */
static void
ngx_http_process_request_headers(ngx_event_t *rev)
{
    u_char                     *p;
    size_t                      len;
    ssize_t                     n;
    ngx_int_t                   rc, rv;
    ngx_table_elt_t            *h;
    ngx_connection_t           *c;
    ngx_http_header_t          *hh;
    ngx_http_request_t         *r;
    ngx_http_core_srv_conf_t   *cscf;
    ngx_http_core_main_conf_t  *cmcf;

    /* 获取当前读事件所对应的连接 */
    c = rev->data;
    /* 获取当前连接的HTTP请求 */
    r = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, rev->log, 0,
                   "http process request header line");

    /* 若当前读事件超时，则关闭该请求，并退出 */
    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
        c->timedout = 1;
        ngx_http_close_request(r, NGX_HTTP_REQUEST_TIME_OUT);
        return;
    }

    /* 获取ngx_http_core_module模块的main级别配置项结构 */
    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

    /* 表示当前请求头部未解析完毕 */
    rc = NGX_AGAIN;

    for ( ;; ) {

        if (rc == NGX_AGAIN) {
            /* 若当前请求头部未解析完毕，则首先判断接收缓冲区是否有内存空间再次接收请求数据 */

            if (r->header_in->pos == r->header_in->end) {

                /* 若接收缓冲区没有足够内存空间，则分配更大的内存空间 */
                rv = ngx_http_alloc_large_header_buffer(r, 0);

                if (rv == NGX_ERROR) {
                    ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                    return;
                }

                if (rv == NGX_DECLINED) {
                    p = r->header_name_start;

                    r->lingering_close = 1;

                    if (p == NULL) {
                        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                                      "client sent too large request");
                        ngx_http_finalize_request(r,
                                            NGX_HTTP_REQUEST_HEADER_TOO_LARGE);
                        return;
                    }

                    len = r->header_in->end - p;

                    if (len > NGX_MAX_ERROR_STR - 300) {
                        len = NGX_MAX_ERROR_STR - 300;
                        p[len++] = '.'; p[len++] = '.'; p[len++] = '.';
                    }

                    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                                  "client sent too long header line: \"%*s\"",
                                  len, r->header_name_start);

                    ngx_http_finalize_request(r,
                                            NGX_HTTP_REQUEST_HEADER_TOO_LARGE);
                    return;
                }
            }

            /* 读取未解析请求数据 */
            n = ngx_http_read_request_header(r);

            /* 若没有可读的数据，或读取失败，则直接退出 */
            if (n == NGX_AGAIN || n == NGX_ERROR) {
                return;
            }
        }

        /* the host header could change the server configuration context */

        /* 获取ngx_http_core_module模块的srv级别配置项结构 */
        cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

        /* 开始解析HTTP请求头部 */
        rc = ngx_http_parse_header_line(r, r->header_in,
                                        cscf->underscores_in_headers);

        /* 解析出一行请求头部（注意：一行请求头部只是HTTP请求头部的一部分） */
        if (rc == NGX_OK) {

            /* 设置当前请求的长度 */
            r->request_length += r->header_in->pos - r->header_name_start;

            /*
             * 若当前解析出来的一行请求头部是非法的，或Nginx当前版本不支持，
             * 则记录错误日志，并继续解析下一行请求头部；
             */
            if (r->invalid_header && cscf->ignore_invalid_headers) {

                /* there was error while a header line parsing */

                ngx_log_error(NGX_LOG_INFO, c->log, 0,
                              "client sent invalid header line: \"%*s\"",
                              r->header_end - r->header_name_start,
                              r->header_name_start);
                continue;
            }

            /* a header line has been parsed successfully */

            /*
             * 若当前解析出来的一行请求头部是合法的，表示成功解析出该行请求头部，
             * 将该行请求头部保存在当前请求的headers_in的headers链表中；
             * 接着继续解析下一行请求头部；
             */
            h = ngx_list_push(&r->headers_in.headers);
            if (h == NULL) {
                ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }

            /* 设置请求头部名称的hash值 */
            h->hash = r->header_hash;

            h->key.len = r->header_name_end - r->header_name_start;
            h->key.data = r->header_name_start;
            h->key.data[h->key.len] = '\0';

            h->value.len = r->header_end - r->header_start;
            h->value.data = r->header_start;
            h->value.data[h->value.len] = '\0';

            h->lowcase_key = ngx_pnalloc(r->pool, h->key.len);
            if (h->lowcase_key == NULL) {
                ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }

            if (h->key.len == r->lowcase_index) {
                ngx_memcpy(h->lowcase_key, r->lowcase_header, h->key.len);

            } else {
                ngx_strlow(h->lowcase_key, h->key.data, h->key.len);
            }

            hh = ngx_hash_find(&cmcf->headers_in_hash, h->hash,
                               h->lowcase_key, h->key.len);

            if (hh && hh->handler(r, h, hh->offset) != NGX_OK) {
                return;
            }

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http header: \"%V: %V\"",
                           &h->key, &h->value);

            continue;
        }

        /* 若成功解析所有请求头部，则接下来就开始处理该请求 */
        if (rc == NGX_HTTP_PARSE_HEADER_DONE) {

            /* a whole header has been parsed successfully */

            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http header done");

            r->request_length += r->header_in->pos - r->header_name_start;

            /* 设置当前请求的解析状态 */
            r->http_state = NGX_HTTP_PROCESS_REQUEST_STATE;

            /*
             * 调用该函数主要目的有两个：
             * 1、根据HTTP头部的host字段，调用ngx_http_find_virtual_server查找虚拟主机的配置块；
             * 2、对HTTP请求头部协议版本进行检查，例如http1.1版本，host头部不能为空，否则会返回400 Bad Request错误；
             */
            rc = ngx_http_process_request_header(r);

            if (rc != NGX_OK) {
                return;
            }

            /* 开始处理当前请求 */
            ngx_http_process_request(r);

            return;
        }

        /* 表示当前行的请求头部未解析完毕，则继续读取请求数据进行解析 */
        if (rc == NGX_AGAIN) {

            /* a header line parsing is still not complete */

            continue;
        }

        /* rc == NGX_HTTP_PARSE_INVALID_HEADER: "\r" is not followed by "\n" */

        /* 解析请求头部出错，则关闭该请求，并退出 */
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "client sent invalid header line: \"%*s\\r...\"",
                      r->header_end - r->header_name_start,
                      r->header_name_start);
        ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
        return;
    }
}
```
处理 HTTP 请求

前面的步骤已经接收到完整的 HTTP 请求头部，此时，已经有足够的信息开始处理HTTP 请求。处理HTTP 请求的过程有11 个 HTTP 阶段，在不同的阶段由各个 HTTP 模块进行处理。有关多阶段处理请求的描述可参考《HTTP request processing phases in Nginx》；
ngx_http_process_request 处理HTTP 请求函数执行流程：
若当前读事件在定时器机制中，则调用 ngx_del_timer 函数将其从定时器机制中移除，因为在处理HTTP 请求时不存在接收HTTP 请求头部超时的问题；
由于处理 HTTP 请求不需要再接收 HTTP 请求行或头部，则需重新设置当前连接读、写事件的回调方法，读、写事件的回调方法都设置为 ngx_http_request_handler，即后续处理 HTTP 请求的过程都是通过该方法进行；
设置当前请求 ngx_http_request_t 结构体中的成员read_event_handler 的回调方法为ngx_http_block_reading，该回调方法实际不做任何操作，即在处理请求时不会对请求的读事件进行任何处理，除非某个HTTP模块重新设置该回调方法；
接下来调用函数 ngx_http_handler 开始处理HTTP 请求；
调用函数 ngx_http_run_posted_requests 处理post 子请求；
函数 ngx_http_process_request 在文件src/http/ngx_http_request.c 中定义如下：
```
/* 处理HTTP请求 */
void
ngx_http_process_request(ngx_http_request_t *r)
{
    ngx_connection_t  *c;

    /* 获取当前请求所对应的连接 */
    c = r->connection;

#if (NGX_HTTP_SSL)
    ...

#endif

    /*
     * 由于现在不需要再接收HTTP请求头部超时问题，
     * 则需要把当前连接的读事件从定时器机制中删除；
     * timer_set为1表示读事件已添加到定时器机制中，
     * 则将其从定时器机制中删除，0表示不在定时器机制中；
     */
    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

#if (NGX_STAT_STUB)
    ...
#endif

    /* 重新设置当前连接的读、写事件的回调方法 */
    c->read->handler = ngx_http_request_handler;
    c->write->handler = ngx_http_request_handler;

    /*
     * 设置请求读事件的回调方法，
     * 其实ngx_http_block_reading函数实际对读事件不做任何处理；
     * 即在处理请求时，不会对读事件任何操作，除非有HTTP模块重新设置处理方法；
     */
    r->read_event_handler = ngx_http_block_reading;

    /* 开始处理各个HTTP模块的handler方法，该函数定义于ngx_http_core_module.c中*/
    ngx_http_handler(r);

    /* 处理post请求 */
    ngx_http_run_posted_requests(c);
}
```
ngx_http_handler 函数的执行流程：
检查当前请求 ngx_http_request_t 的 internal 标志位：
若 internal 标志位为 0，表示当前请求不需要重定向，判断是否使用 keepalive 机制，并设置phase_handler 序号为0，表示执行ngx_http_phase_engine_t 结构成员ngx_http_phase_handler_t *handlers数组中的第一个回调方法；
若 internal 标志位为 1，表示需要将当前请求做内部跳转，并将 phase_handler 设置为server_rewriter_index，表示执行ngx_http_phase_engine_t 结构成员ngx_http_phase_handler_t *handlers 数组在NGX_HTTP_SERVER_REWRITE_PHASE 处理阶段的第一个回调方法；
设置当前请求 ngx_http_request_t 的成员写事件write_event_handler 为ngx_http_core_run_phases；
执行n gx_http_core_run_phases 方法；
函数 ngx_http_handler 在文件 src/http/ngx_http_core_module.c 中定义如下：
```
void
ngx_http_handler(ngx_http_request_t *r)
{
    ngx_http_core_main_conf_t  *cmcf;

    r->connection->log->action = NULL;

    r->connection->unexpected_eof = 0;

    /* 若当前请求的internal标志位为0，表示不需要重定向 */
    if (!r->internal) {
        /* 下面语句是决定是否使用keepalive机制 */
        switch (r->headers_in.connection_type) {
        case 0:
            r->keepalive = (r->http_version > NGX_HTTP_VERSION_10);
            break;

        case NGX_HTTP_CONNECTION_CLOSE:
            r->keepalive = 0;
            break;

        case NGX_HTTP_CONNECTION_KEEP_ALIVE:
            r->keepalive = 1;
            break;
        }

        /* 设置延迟关闭标志位 */
        r->lingering_close = (r->headers_in.content_length_n > 0
                              || r->headers_in.chunked);
        /*
         * phase_handler序号设置为0，表示执行ngx_http_phase_engine_t结构体成员
         * ngx_http_phase_handler_t *handlers数组中的第一个回调方法；
         */
        r->phase_handler = 0;

    } else {
    /* 若当前请求的internal标志位为1，表示需要做内部跳转 */
        /* 获取ngx_http_core_module模块的main级别的配置项结构 */
        cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);
        /*
         * 将phase_handler序号设为server_rewriter_index，
         * 该phase_handler序号是作为ngx_http_phase_engine_t结构中成员
         * ngx_http_phase_handler_t *handlers回调方法数组的序号，
         * 即表示回调方法在该数组中所处的位置；
         *
         * server_rewrite_index则是handlers数组中NGX_HTTP_SERVER_REWRITE_PHASE阶段的
         * 第一个ngx_http_phase_handler_t回调的方法；
         */
        r->phase_handler = cmcf->phase_engine.server_rewrite_index;
    }

    r->valid_location = 1;
#if (NGX_HTTP_GZIP)
    r->gzip_tested = 0;
    r->gzip_ok = 0;
    r->gzip_vary = 0;
#endif

    /* 设置当前请求写事件的回调方法 */
    r->write_event_handler = ngx_http_core_run_phases;
    /*
     * 执行该回调方法，将调用各个HTTP模块共同处理当前请求，
     * 各个HTTP模块按照11个HTTP阶段进行处理；
     */
    ngx_http_core_run_phases(r);
}
```
ngx_http_core_run_phases 函数的执行流程：
判断每个 ngx_http_phase_handler_t 处理阶段是否实现checker 方法：
若实现 checker 方法，则执行 phase_handler 序号在 ngx_http_phase_handler_t *handlers数组中指定的checker 方法；执行完checker 方法，若返回NGX_OK 则退出；若返回非NGX_OK，则继续执行下一个HTTP 模块在该阶段的checker 方法；
若没有实现 checker 方法，则直接退出；
函数 ngx_http_core_run_phases 在文件src/http/ngx_http_core_module.c 中定义如下：
```
void
ngx_http_core_run_phases(ngx_http_request_t *r)
{
    ngx_int_t                   rc;
    ngx_http_phase_handler_t   *ph;
    ngx_http_core_main_conf_t  *cmcf;

    /* 获取ngx_http_core_module模块的main级别的配置项结构体 */
    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

    /* 获取各个HTTP模块处理请求的回调方法数组 */
    ph = cmcf->phase_engine.handlers;

    /* 若实现了checker方法 */
    while (ph[r->phase_handler].checker) {

        /* 执行phase_handler序号在数组中指定的checker方法 */
        rc = ph[r->phase_handler].checker(r, &ph[r->phase_handler]);

        /* 成功执行checker方法，则退出，否则继续执行下一个HTTP模块的checker方法 */
        if (rc == NGX_OK) {
            return;
        }
    }
}
```
处理子请求

post 子请求是基于 subrequest 机制的，首先看下 post 子请求结构体类型：
```
/* 子请求的单链表结构 */
typedef struct ngx_http_posted_request_s  ngx_http_posted_request_t;

struct ngx_http_posted_request_s {
    /* 指向当前待处理子请求的ngx_http_request_t结构体 */
    ngx_http_request_t               *request;
    /* 指向下一个子请求 */
    ngx_http_posted_request_t        *next;
};
```
在请求结构体 ngx_http_request_t 中有一个与post 子请求相关的成员posted_requests，该成员把各个post 子请求按照子请求结构体ngx_http_posted_request_t 的结构连接成单链表的形式，请求结构体ngx_http_request_t 中main 成员是子请求的原始请求，parent 成员是子请求的父请求。下面是子请求的处理过程。
ngx_http_run_posted_requests 函数执行流程：
判断当前连接是否已被销毁（即标志位 destroyed 是否为0），若被销毁则直接return 退出，否则继续执行；
获取原始请求的子请求链表，若子请求链表为空（表示没有 post 请求）则直接return 退出，否则继续执行；
遍历子请求链表，执行每个 post 请求的写事件回调方法write_event_handler；
函数 ngx_http_run_posted_requests 在文件src/http/ngx_http_request.c 中定义如下：
```
void
ngx_http_run_posted_requests(ngx_connection_t *c)
{
    ngx_http_request_t         *r;
    ngx_http_log_ctx_t         *ctx;
    ngx_http_posted_request_t  *pr;

    for ( ;; ) {

        /* 若当前连接已被销毁，则直接退出 */
        if (c->destroyed) {
            return;
        }

        /* 获取当前连接所对应的请求 */
        r = c->data;
        /* 获取原始请求的子请求单链表 */
        pr = r->main->posted_requests;

        /* 若子请求单链表为空，则直接退出 */
        if (pr == NULL) {
            return;
        }

        /* 将原始请求的posted_requests指向单链表的下一个post请求 */
        r->main->posted_requests = pr->next;

        /* 获取子请求链表中的第一个post请求 */
        r = pr->request;

        ctx = c->log->data;
        ctx->current_request = r;

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http posted request: \"%V?%V\"", &r->uri, &r->args);

        /*
         * 调用当前post请求写事件的回调方法write_event_handler；
         * 子请求不被网络事件驱动，因此不需要调用read_event_handler；
         */
        r->write_event_handler(r);
    }
}
```
处理 HTTP 请求包体

下面开始要分析 HTTP 框架是如何处理HTTP 请求包体，HTTP 框架有两种处理请求包体的方法：接收请求包体、丢弃请求包体；但是必须要注意的是丢弃请求包体并不意味着就不接受请求包体，只是把接收到的请求包体进行丢弃，不进一步对其进行处理。
其中有一个很重要的成员就是请求结构体 ngx_http_request_t  中的引用计数count，引用计数是用来决定是否真正结束当前请求，若引用计数为0 时，表示没有其他动作在处理该请求，则可以终止该请求；若引用计数不为0 时，表示当前请求还有其他动作在操作，因此不能结束当前请求，以免发生错误；那怎么样控制这个引用计数呢？例如，当一个请求添加新事件，或是把一些原本从定时器、epoll 事件机制中移除的事件从新加入到其中等等，出现这些情况都是要对引用计数增加1；当要结束请求时，首先会把引用计数减1，并判断该引用计数是否为0，再进一步判断是否决定真的结束当前请求。
接收 HTTP 请求包体

HTTP 请求包体保存在结构体 ngx_http_request_body_t 中，该结构体是存放在保存着请求结构体 ngx_http_request_t 的成员 request_body 中，该结构体定义如下：
```
/* 存储HTTP请求包体的结构体ngx_http_request_body_t */
typedef struct {
    /* 存放HTTP请求包体的临时文件 */
    ngx_temp_file_t                  *temp_file;
    /*
     * 指向接收HTTP请求包体的缓冲区链表表头，
     * 因为当一个缓冲区ngx_buf_t无法容纳所有包体时，就需要多个缓冲区形成链表；
     */
    ngx_chain_t                      *bufs;
    /* 指向当前保存HTTP请求包体的缓冲区 */
    ngx_buf_t                        *buf;
    /*
     * 根据content-length头部和已接收包体长度，计算还需接收的包体长度；
     * 即当前剩余的请求包体大小；
     */
    off_t                             rest;
    /* 接收HTTP请求包体缓冲区链表空闲缓冲区 */
    ngx_chain_t                      *free;
    /* 接收HTTP请求包体缓冲区链表已使用的缓冲区 */
    ngx_chain_t                      *busy;
    /* 保存chunked的解码状态，供ngx_http_parse_chunked方法使用 */
    ngx_http_chunked_t               *chunked;
    /*
     * HTTP请求包体接收完毕后执行的回调方法；
     * 即ngx_http_read_client_request_body方法传递的第 2 个参数；
     */
    ngx_http_client_body_handler_pt   post_handler;
} ngx_http_request_body_t;
```
接收 HTTP 请求包体 ngx_http_read_client_request_body 函数执行流程：
原始请求引用计算 r->main->count 增加 1；引用计数 count 的管理是：当逻辑开启流程时，引用计数就增加1，结束此流程时，引用计数就减1。在ngx_http_read_client_request_body 函数中，首先将原始请求的引用计数增加1，当遇到异常终止时，引用计数会在该函数返回之前减1；若正常结束时，引用计数由post_handler回调方法继续维护；
判断当前请求包体是否已被完整接收（r->request_body 为1）或被丢弃（r->discard_body为1），若满足其中一个则不需要再次接收请求包体，直接执行post_handler 回调方法，并NGX_OK 从当前函数返回；
若需要接收 HTTP 请求包体，则首先调用 ngx_http_test_expect 方法，检查客户端是否发送 Expect:100-continue 头部期望发送请求包体，服务器会回复 HTTP/1.1 100 Continue 表示允许客户端发送请求包体；
分配当前请求 ngx_http_request_t 结构体request_body 成员，准备接收请求包体；
检查请求的 content-length 头部，若请求头部的 content-length 字段小于0，则表示不需要继续接收请求包体（即已经接收到完整的请求包体），直接执行post_handler 回调方法，并 NGX_OK 从当前函数返回；
若请求头部的 content-length 字段大于 0，则表示需要继续接收请求包体。首先判断当前请求 ngx_http_request_t 的header_in 成员是否存在未处理数据，若存在未被处理的数据，表示该缓冲区header_in 在接收请求头部期间已经预接收了请求包体，因为在接收HTTP 请求头部期间有可能预接收请求包体，由于在接收请求包体之前，请求头部已经被接收完毕，所以若该缓冲区存在未被处理的数据，那就是请求包体。
若 header_in 缓冲区存在未被处理的数据，即是预接收的请求包体，首先检查缓冲区请求包体长度preread 是否大于请求包体长度的content-length 字段，若大于则表示已经接收到完整的HTTP 请求包体，不需要继续接收，则执行post_handler 回调方法；
若 header_in 缓冲区存在未被处理的数据，即是预接收的请求包体，但是缓冲区请求包体长度preread 小于请求包体长度的content-length 字段，表示已接收的请求包体不完整，则需要继续接收请求包体。调用函数ngx_http_request_body_filte 解析并把已接收的请求包体挂载到请求ngx_http_request_t r 的 request_body->bufs，header_in 缓冲区剩余的空间足够接收剩余的请求包体大小rest，则不需要分配新的缓冲区，进而设置当前请求ngx_http_request_t  的 read_event_handler 读事件回调方法为ngx_http_read_client_request_body_handler，写事件write_event_handler 回调方法为ngx_http_request_empty_handler (即不执行任何操作)，然后调用方法ngx_http_do_read_client_request_body 真正接收HTTP 请求包体，该方法将TCP 连接上的套接字缓冲区中的字符流全部读取出来，并判断是否需要写入到临时文件，以及是否接收全部的请求包体，同时在接收到完整包体后执行回调方法post_handler；
若 header_in 缓冲区存在未被处理的数据，即是预接收的请求包体，但是缓冲区请求包体长度preread 小于请求包体长度的content-length 字段，或者header_in 缓冲区不存在未被处理的数据，且header_in 剩余的空间不足够接收HTTP 请求包体，则会重新分配接收请求包体的缓冲区，再进而设置当前请求ngx_http_request_t 的read_event_handler 读事件回调方法为ngx_http_read_client_request_body_handler，写事件write_event_handler 回调方法为ngx_http_request_empty_handler (即不执行任何操作)，然后调用方法ngx_http_do_read_client_request_body 真正接收HTTP 请求包体；
函数 ngx_http_read_client_request_body 在文件src/http/ngx_http_request_body.c 中定义如下：
```
/* 接收HTTP请求包体 */
ngx_int_t
ngx_http_read_client_request_body(ngx_http_request_t *r,
    ngx_http_client_body_handler_pt post_handler)
{
    size_t                     preread;
    ssize_t                    size;
    ngx_int_t                  rc;
    ngx_buf_t                 *b;
    ngx_chain_t                out, *cl;
    ngx_http_request_body_t   *rb;
    ngx_http_core_loc_conf_t  *clcf;

    /*
     * 当有逻辑开启流程时，引用计数会增加1，此流程结束时，引用计数将减1；
     * 在ngx_http_read_client_request_body方法中，首先将原始请求引用计数增加1，
     * 当遇到异常终止时，则在该函数返回前会将引用计数减1,；
     * 若正常结束时，引用计数由post_handler方法继续维护；
     */
    /* 原始请求的引用计数count加1 */
    r->main->count++;

#if (NGX_HTTP_SPDY)
    if (r->spdy_stream && r == r->main) {
        rc = ngx_http_spdy_read_request_body(r, post_handler);
        goto done;
    }
#endif

    /* HTTP请求包体未被处理时，request_body结构是不被分配的，只有处理时才会分配 */
    /*
     * 若当前HTTP请求不是原始请求，或HTTP请求包体已被读取或被丢弃；
     * 则直接执行HTTP模块的回调方法post_handler，并返回NGX_OK；
     */
    if (r != r->main || r->request_body || r->discard_body) {
        post_handler(r);
        return NGX_OK;
    }

    /*
     * ngx_http_test_expect 用于检查客户端是否发送Expect:100-continue头部，
     * 若客户端已发送该头部表示期望发送请求包体数据，则服务器回复HTTP/1.1 100 Continue；
     * 具体意义是：客户端期望发送请求包体，服务器允许客户端发送，
     * 该函数返回NGX_OK；
     */
    if (ngx_http_test_expect(r) != NGX_OK) {
        rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        goto done;
    }

    /* 只有在确定要接收请求包体时才分配存储HTTP请求包体的结构体 ngx_http_request_body_t 空间 */
    rb = ngx_pcalloc(r->pool, sizeof(ngx_http_request_body_t));
    if (rb == NULL) {
        rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        goto done;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     rb->bufs = NULL;
     *     rb->buf = NULL;
     *     rb->free = NULL;
     *     rb->busy = NULL;
     *     rb->chunked = NULL;
     */

    /* 初始化存储请求包体结构成员 */
    rb->rest = -1;/* 待接收HTTP请求包体的大小 */
    rb->post_handler = post_handler;/* 接收完包体后的回调方法 */

    /* 令当前请求的post_body成员指向存储请求包体结构 */
    r->request_body = rb;

    /*
     * 若指定HTTP请求包体的content_length字段小于0，则表示不需要接收包体；
     * 执行post_handler方法，并返回；
     */
    if (r->headers_in.content_length_n < 0 && !r->headers_in.chunked) {
        post_handler(r);
        return NGX_OK;
    }

    /* 若指定HTTP请求包体的content_length字段大于0，则表示需要接收包体；*/

    /*
     * 在请求结构ngx_http_request_t 成员中header_in缓冲区保存的是HTTP请求头部，
     * 由于在处理HTTP请求之前，HTTP头部已被完整接收，所以若header_in缓冲区里面
     * 还存在未处理的数据，则证明在接收HTTP请求头部期间，已经预接收了HTTP请求包体；
     */
    preread = r->header_in->last - r->header_in->pos;

    /*
     * 若header_in缓冲区存在预接收的HTTP请求包体，
     * 则计算还需接收HTTP请求包体的大小rest；
     */
    if (preread) {

        /* there is the pre-read part of the request body */

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http client request body preread %uz", preread);

        /* 将out的缓冲区指向header_in缓冲区中的请求包体数据 */
        out.buf = r->header_in;
        out.next = NULL;

        /*
         * 将预接收的HTTP请求包体数据添加到r->request_body->bufs中，
         * 即将请求包体存储在新分配的ngx_http_request_body_t rb 结构体的bufs中；
         */
        rc = ngx_http_request_body_filter(r, &out);

        if (rc != NGX_OK) {
            goto done;
        }

        /* 若ngx_http_request_body_filter返回NGX_OK，则继续执行以下程序 */

        /* 更新当前HTTP请求长度：包括请求头部与请求包体 */
        r->request_length += preread - (r->header_in->last - r->header_in->pos);

        /*
         * 若已接收的请求包体不完整，即rest大于0，表示需要继续接收请求包体；
         * 若此时header_in缓冲区仍然有足够的剩余空间接收剩余的请求包体长度，
         * 则不再分配缓冲区内存；
         */
        if (!r->headers_in.chunked
            && rb->rest > 0
            && rb->rest <= (off_t) (r->header_in->end - r->header_in->last))
        {
            /* the whole request body may be placed in r->header_in */

            b = ngx_calloc_buf(r->pool);
            if (b == NULL) {
                rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
                goto done;
            }

            b->temporary = 1;
            b->start = r->header_in->pos;
            b->pos = r->header_in->pos;
            b->last = r->header_in->last;
            b->end = r->header_in->end;

            rb->buf = b;

            /* 设置当前请求读事件的回调方法 */
            r->read_event_handler = ngx_http_read_client_request_body_handler;
            r->write_event_handler = ngx_http_request_empty_handler;

            /*
             * 真正开始接收请求包体数据；
             * 将TCP套接字连接缓冲区中当前的字符流全部读取出来，
             * 并判断是否需要写入临时文件，以及是否接收全部的请求包体，
             * 同时在接收到完整包体后执行回调方法post_handler；
             */
            rc = ngx_http_do_read_client_request_body(r);
            goto done;
        }

    } else {
        /*
         * 若在接收HTTP请求头部过程没有预接收HTTP请求包体数据，
         * 或者预接收了不完整的HTTP请求包体，但是header_in缓冲区不够继续存储剩余的包体；
         * 进一步计算待需接收HTTP请求的大小rest；
         */
        /* set rb->rest */

        if (ngx_http_request_body_filter(r, NULL) != NGX_OK) {
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            goto done;
        }
    }

    /* 若rest为0，表示无需继续接收HTTP请求包体，即已接收到完整的HTTP请求包体 */
    if (rb->rest == 0) {/* 若已接收完整的HTTP请求包体 */
        /* the whole request body was pre-read */

        /*
         * 检查client_body_in_file_only配置项是否打开，若打开，
         * 则将r->request_body->bufs中的包体数据写入到临时文件；
         */
        if (r->request_body_in_file_only) {
            if (ngx_http_write_request_body(r) != NGX_OK) {
                rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
                goto done;
            }

            if (rb->temp_file->file.offset != 0) {

                cl = ngx_chain_get_free_buf(r->pool, &rb->free);
                if (cl == NULL) {
                    rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
                    goto done;
                }

                b = cl->buf;

                ngx_memzero(b, sizeof(ngx_buf_t));

                b->in_file = 1;
                b->file_last = rb->temp_file->file.offset;
                b->file = &rb->temp_file->file;

                rb->bufs = cl;

            } else {
                rb->bufs = NULL;
            }
        }

        /* 执行回调方法 */
        post_handler(r);

        return NGX_OK;
    }

    /* rest小于0表示出错 */
    if (rb->rest < 0) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "negative request body rest");
        rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        goto done;
    }

    /* 若rest大于0，则表示需要继续接收HTTP请求包体数据，执行以下程序 */

    /* 获取ngx_http_core_module模块的loc级别配置项结构 */
    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    /* 获取缓存请求包体的buffer缓冲区大小 */
    size = clcf->client_body_buffer_size;
    size += size >> 2;

    /* TODO: honor r->request_body_in_single_buf */

    if (!r->headers_in.chunked && rb->rest < size) {
        size = (ssize_t) rb->rest;

        if (r->request_body_in_single_buf) {
            size += preread;
        }

    } else {
        size = clcf->client_body_buffer_size;
    }

    rb->buf = ngx_create_temp_buf(r->pool, size);
    if (rb->buf == NULL) {
        rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        goto done;
    }

    /* 设置当前请求读事件的回调方法 */
    r->read_event_handler = ngx_http_read_client_request_body_handler;
    r->write_event_handler = ngx_http_request_empty_handler;

    /* 接收请求包体 */
    rc = ngx_http_do_read_client_request_body(r);

done:

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        r->main->count--;
    }

    return rc;
}
```
读取 HTTP 请求包体 ngx_http_do_read_client_request_body 函数执行流程：
若 request_body->buf 缓冲区没有剩余的空间，则先调用函数ngx_http_write_request_body 将该缓冲区的数据写入到文件中；此时，该缓冲区就有空间；或者 request_body->buf 缓冲区有剩余的空间；接着分别计算request_body->buf 缓冲区所剩余的可用空间大小 size、待接收 HTTP 请求包体的长度 rest；若当前缓冲区剩余大小足够接收HTTP 请求包体，即size > rest，则调用recv 方法从 TCP 连接套接字缓冲区中读取请求包体数据到当前缓冲区request_body->buf 中，下面根据recv 方法的返回值n 做不同的判断：
返回值 n 为 NGX_AGAIN，表示 TCP 连接套接字缓冲区上的字符流未读取完毕，则需继续读取；
返回值 n 为 0 或 NGX_ERROR，表示读取失败，设置当前请求的errno 标志位错误编码，并退出；
返回值 n 不是以上的值，则表示读取成功，此时，更新当缓冲区request_body->buf的使用情况，更新当前请求的长度。判断已成功读取的长度n 是否等于待接收HTTP 请求包体的长度rest，若n = rest，则将已读取的请求包体挂载到当前请求的request body->buf链表中；并重新更新待接收的剩余请求包体长度rest 值；
根据 rest 值判断是否已经接收到完整的 HTTP 请求包体：
rest 值大于 0，表示未接收到完整的 HTTP 请求包体，且当前套接字缓冲区已经没有可读数据，则需要调用函数ngx_add_timer 将当前连接的读事件添加到定时器机制，调用函数ngx_handler_read_event 将当前连接读事件注册到epoll 事件机制中，等待可读事件的发生；此时，ngx_http_do_read_client_reuqest_body 返回NGX_AGAIN；
rest 等于 0，表示已经接收到完整的 HTTP 请求包体，则把读事件从定时器机制移除，把缓冲区数据写入到文件中，设置读事件的回调方法为ngx_http_block_reading（不进行任何操作），最后执行post_handler 回调方法；
函数 ngx_http_do_read_client_request_body 在文件src/http/ngx_http_request_body.c 中定义如下：
```
/* 读取HTTP请求包体 */
static ngx_int_t
ngx_http_do_read_client_request_body(ngx_http_request_t *r)
{
    off_t                      rest;
    size_t                     size;
    ssize_t                    n;
    ngx_int_t                  rc;
    ngx_buf_t                 *b;
    ngx_chain_t               *cl, out;
    ngx_connection_t          *c;
    ngx_http_request_body_t   *rb;
    ngx_http_core_loc_conf_t  *clcf;

    /* 获取当前请求所对应的连接 */
    c = r->connection;
    /* 获取当前请求的请求包体结构体 */
    rb = r->request_body;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http read client request body");

    for ( ;; ) {
        for ( ;; ) {
            /* 若当前缓冲区buf已满 */
            if (rb->buf->last == rb->buf->end) {

                /* pass buffer to request body filter chain */

                out.buf = rb->buf;
                out.next = NULL;

                rc = ngx_http_request_body_filter(r, &out);

                if (rc != NGX_OK) {
                    return rc;
                }

                /* write to file */

                /* 将缓冲区的字符流写入文件 */
                if (ngx_http_write_request_body(r) != NGX_OK) {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }

                /* update chains */

                rc = ngx_http_request_body_filter(r, NULL);

                if (rc != NGX_OK) {
                    return rc;
                }

                if (rb->busy != NULL) {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }

                /* 由于已经将当前缓冲区的字符流写入到文件，则该缓冲区有空间继续使用 */
                rb->buf->pos = rb->buf->start;
                rb->buf->last = rb->buf->start;
            }

            /* 计算当前缓冲区剩余的可用空间size */
            size = rb->buf->end - rb->buf->last;
            /* 计算需要继续接收请求包体的大小rest */
            rest = rb->rest - (rb->buf->last - rb->buf->pos);

            /* 若当前缓冲区有足够的空间接收剩余的请求包体，则不需要再分配缓冲区 */
            if ((off_t) size > rest) {
                size = (size_t) rest;
            }

            /* 从TCP连接套接字读取请求包体，并保存到当前缓冲区 */
            n = c->recv(c, rb->buf->last, size);

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                           "http client request body recv %z", n);

            /* 若连接上套接字字符流还未读取完整，则继续读取 */
            if (n == NGX_AGAIN) {
                break;
            }

            if (n == 0) {
                ngx_log_error(NGX_LOG_INFO, c->log, 0,
                              "client prematurely closed connection");
            }

            /* 读取错误，设置错误编码 */
            if (n == 0 || n == NGX_ERROR) {
                c->error = 1;
                return NGX_HTTP_BAD_REQUEST;
            }

            /* 调整当前缓冲区的使用情况 */
            rb->buf->last += n;
            /* 设置已接收HTTP请求长度 */
            r->request_length += n;

            /* 若已完整接收HTTP请求包体，则将该包体数据存储到r->request_body->bufs中 */
            if (n == rest) {
                /* pass buffer to request body filter chain */

                out.buf = rb->buf;
                out.next = NULL;

                /* 将已读取的请求包体数据挂载到r->request_body->bufs中，并重新计算rest值 */
                rc = ngx_http_request_body_filter(r, &out);

                if (rc != NGX_OK) {
                    return rc;
                }
            }

            if (rb->rest == 0) {
                break;
            }

            if (rb->buf->last < rb->buf->end) {
                break;
            }
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http client request body rest %O", rb->rest);

        if (rb->rest == 0) {
            break;
        }

        /*
         * 若未接接收到完整的HTTP请求包体，且当前连接读事件未准备就绪，
         * 则需将读事件添加到定时器机制，注册到epoll事件机制中，等待可读事件发生；
         */
        if (!c->read->ready) {
            clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
            ngx_add_timer(c->read, clcf->client_body_timeout);

            if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            return NGX_AGAIN;
        }
    }

    /* 到此，已经完整接收到HTTP请求，则需要将读事件从定时器机制中移除 */
    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    /* 若设置将请求包体保存到临时文件，则必须将缓冲区的请求包体数据写入到文件中 */
    if (rb->temp_file || r->request_body_in_file_only) {

        /* save the last part */

        /* 将缓冲区的请求包体数据写入到文件中 */
        if (ngx_http_write_request_body(r) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (rb->temp_file->file.offset != 0) {

            cl = ngx_chain_get_free_buf(r->pool, &rb->free);
            if (cl == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            b = cl->buf;

            ngx_memzero(b, sizeof(ngx_buf_t));

            b->in_file = 1;
            b->file_last = rb->temp_file->file.offset;
            b->file = &rb->temp_file->file;

            rb->bufs = cl;

        } else {
            rb->bufs = NULL;
        }
    }

    /*
     * 由于已经完成请求包体的接收，则需重新设置读事件的回调方法；
     * read_event_handler 设置为 ngx_http_block_reading 表示阻塞读事件
     * 即再有读事件发生将不会做任何处理；
     */
    r->read_event_handler = ngx_http_block_reading;

    /* 接收HTTP请求包体完毕后，调用回调方法post_handler */
    rb->post_handler(r);

    return NGX_OK;
}
```
ngx_http_read_client_request_body_handler 方法执行流程：
检查连接上读事件 timeout 标志位是否超时，若超时则调用函数ngx_http_finalize_request 终止当前请求；
若不超时，调用函数 ngx_http_do_read_client_request_body 开始读取HTTP 请求包体数据；
函数 ngx_http_read_client_request_body_handler 在文件src/http/ngx_http_request_body.c 中定义如下：
```
static void
ngx_http_read_client_request_body_handler(ngx_http_request_t *r)
{
    ngx_int_t  rc;

    /* 检查连接上读事件timeout标志位是否超时，若超时则终止该请求 */
    if (r->connection->read->timedout) {
        r->connection->timedout = 1;
        ngx_http_finalize_request(r, NGX_HTTP_REQUEST_TIME_OUT);
        return;
    }

    /* 开始接收HTTP请求包体数据 */
    rc = ngx_http_do_read_client_request_body(r);

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        ngx_http_finalize_request(r, rc);
    }
}

丢弃 HTTP 请求包体

当 HTTP 框架不需要请求包体时，会在接收完该请求包体之后将其丢弃，并不会进行下一步处理，以下是相关函数。
丢弃 HTTP 请求包体 ngx_http_discard_request_body 函数执行流程：
若当前是子请求，或请求包体已经被完整接收，或请求包体已被丢弃，则不需要继续，直接返回 NGX_OK 结束该函数；
调用函数 ngx_http_test_expect 检查客户端是否要发送请求包体，若服务器允许发送，则继续执行；
若当前请求连接上的读事件在定时器机制中（即 timer_set 标志位为1），则将该读事件从定时器机制中移除（丢弃请求包体不需要考虑超时问题，除非设置linger_timer）；
由于此时，待丢弃包体长度 content_length_n 为请求content-length 头部字段大小，所有判断content-length头部字段是否小于0，若小于0，表示已经成功丢弃完整的请求包体，直接返回NGX_OK；若大于0，表示需要继续丢弃请求包体，则继续执行；
检查当前请求的 header_in 缓冲区是否预接收了 HTTP 请求，设此时 header_in 缓冲区里面未处理的数据大小为size，若size 不为0，表示已经预接收了HTTP 请求包体数据，则调用函数ngx_http_discard_request_body_filter 将该请求包体丢弃，并根据已经预接收请求包体长度和请求content-length 头部字段长度，重新计算需要待丢弃请求包体的长度content_length_n 的值；根据ngx_http_discard_request_body_filter 函数的返回值rc 进行不同的判断：
若 rc = NGX_OK，且 content_length_n 的值为 0，则表示已经接收到完整请求包体，并将其丢弃；
若 rc ！= NGX_OK，则表示需要继续接收请求包体，根据content_length_n 的值来表示待丢弃请求包体的长度；
若还需继续丢弃请求包体，则调用函数 ngx_http_read_discard_request_body 读取剩余的请求包体数据，并将其丢弃；并根据该函数返回值rc 不同进行判断：
若 rc = NGX_OK，表示已成功丢弃完整的请求包体；
若 rc ！= NGX_OK，则表示接收到请求包体依然不完整，且此时连接套接字上已经没有剩余数据可读，则设置当前请求读事件的回调方法read_event_handler 为ngx_http_discarded_request_body_handler，并调用函数ngx_handle_read_event 将该请求连接上的读事件注册到epoll 事件机制中，等待可读事件发生以便继续读取请求包体；同时将引用计数增加1（防止继续丢弃包体），当前请求的discard_body 标志位设置为1，表示正在丢弃，并返回NGX_OK（这里并不表示已经成功丢弃完整的请求包体，只是表示ngx_http_discard_request_body 执行完毕，接下来的是等待读事件发生并继续丢弃包体）；
函数 ngx_http_discard_request_body 在文件src/http/ngx_http_request_body.c 中定义如下：
```
/* 丢弃HTTP请求包体 */
ngx_int_t
ngx_http_discard_request_body(ngx_http_request_t *r)
{
    ssize_t       size;
    ngx_int_t     rc;
    ngx_event_t  *rev;

#if (NGX_HTTP_SPDY)
    if (r->spdy_stream && r == r->main) {
        r->spdy_stream->skip_data = NGX_SPDY_DATA_DISCARD;
        return NGX_OK;
    }
#endif

    /*
     * 若当前HTTP请求不是原始请求，或HTTP请求包体已被读取或被丢弃；
     * 则直接返回NGX_OK；
     */
    if (r != r->main || r->request_body || r->discard_body) {
        return NGX_OK;
    }

    /*
     * ngx_http_test_expect 用于检查客户端是否发送Expect:100-continue头部，
     * 若客户端已发送该头部表示期望发送请求包体数据，则服务器回复HTTP/1.1 100 Continue；
     * 具体意义是：客户端期望发送请求包体，服务器允许客户端发送，
     * 该函数返回NGX_OK；
     */
    if (ngx_http_test_expect(r) != NGX_OK) {
        rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* 获取当前连接的读事件 */
    rev = r->connection->read;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, rev->log, 0, "http set discard body");

    /* 若读事件在定时器机制中，则将其移除 */
    if (rev->timer_set) {
        ngx_del_timer(rev);
    }

    /* 若请求content-length头部字段小于0，直接返回NGX_OK */
    if (r->headers_in.content_length_n <= 0 && !r->headers_in.chunked) {
        return NGX_OK;
    }

    /* 获取当前请求header_in缓冲区中预接收请求包体数据 */
    size = r->header_in->last - r->header_in->pos;

    /* 若已经预接收了HTTP请求包体数据 */
    if (size || r->headers_in.chunked) {
        /*
         * 丢弃预接收请求包体数据，并根据预接收请求包体大小与请求content-length头部大小，
         * 重新计算content_length_n的值；
         */
        rc = ngx_http_discard_request_body_filter(r, r->header_in);

        /* 若rc不为NGX_OK表示预接收的请求包体数据不完整，需继续接收 */
        if (rc != NGX_OK) {
            return rc;
        }

        /* 若返回rc=NGX_OK，且待丢弃请求包体大小content-length_n为0，表示已丢弃完整的请求包体 */
        if (r->headers_in.content_length_n == 0) {
            return NGX_OK;
        }
    }

    /* 读取剩余的HTTP请求包体数据，并将其丢弃 */
    rc = ngx_http_read_discarded_request_body(r);

    /* 若已经读取到完整请求包体，则返回NGX_OK */
    if (rc == NGX_OK) {
        r->lingering_close = 0;/* 不需要延迟关闭请求 */
        return NGX_OK;
    }

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    /* rc == NGX_AGAIN */

    /*
     * 若读取到的请求包体依然不完整，但此时已经没有剩余数据可读，
     * 则将当前请求读事件回调方法设置为ngx_http_discard_request_body_handler，
     * 并将读事件注册到epoll事件机制中，等待可读事件发生以便继续读取请求包体；
     */
    r->read_event_handler = ngx_http_discarded_request_body_handler;

    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* 由于已将读事件注册到epoll事件机制中，则引用计数增加1，discard_body标志为1 */
    r->count++;
    r->discard_body = 1;

    return NGX_OK;
}

ngx_http_discarded_request_body_handler 函数执行流程如下：
判断当前请求连接上的读事件是否超时，若超时（即标志位 timeout 为1），则调用函数ngx_http_finalize_request 将引用计数减1，若此时引用计数为0，则终止当前请求；
调用函数 ngx_http_read_discarded_request_body 开始读取请求包体，并将所读取的请求包体丢弃；同时根据该函数的返回值rc 不同进行判断：
若返回值 rc = NGX_OK，表示已经接收到完整请求包体，并成功将其丢弃，则此时设置discard_body 标志位为0，设置lingering_close 标志位为0，并调用函数ngx_http_finalize_request 结束当前请求；
若返回值 rc ！= NGX_OK，则表示读取的请求包体依旧不完整，调用函数ngx_handle_read_event 将读事件注册到epoll 事件机制中，等待可读事件发生；
函数 ngx_http_discarded_request_body_handler 在文件src/http/ngx_http_request_body.c 中定义如下：
void
ngx_http_discarded_request_body_handler(ngx_http_request_t *r)
{
    ngx_int_t                  rc;
    ngx_msec_t                 timer;
    ngx_event_t               *rev;
    ngx_connection_t          *c;
    ngx_http_core_loc_conf_t  *clcf;

    c = r->connection;
    rev = c->read;

    /*
     * 判断读事件是否超时，若超时则调用ngx_http_finalize_request方法将引用计数减1，
     * 若此时引用计数是0，则直接终止该请求；
     */
    if (rev->timedout) {
        c->timedout = 1;
        c->error = 1;
        ngx_http_finalize_request(r, NGX_ERROR);
        return;
    }

    /* 若需要延迟关闭，则设置延迟关闭连接的时间 */
    if (r->lingering_time) {
        timer = (ngx_msec_t) r->lingering_time - (ngx_msec_t) ngx_time();

        if ((ngx_msec_int_t) timer <= 0) {
            r->discard_body = 0;
            r->lingering_close = 0;
            ngx_http_finalize_request(r, NGX_ERROR);
            return;
        }

    } else {
        timer = 0;
    }

    /* 读取剩余请求包体，并将其丢弃 */
    rc = ngx_http_read_discarded_request_body(r);

    /* 若返回rc=NGX_OK，则表示已接收到完整请求包体，并成功将其丢弃 */
    if (rc == NGX_OK) {
        r->discard_body = 0;
        r->lingering_close = 0;
        ngx_http_finalize_request(r, NGX_DONE);
        return;
    }

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        c->error = 1;
        ngx_http_finalize_request(r, NGX_ERROR);
        return;
    }

    /* rc == NGX_AGAIN */

    /* 若读取的请求包体依旧不完整，则再次将读事件注册到epoll事件机制中 */
    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        c->error = 1;
        ngx_http_finalize_request(r, NGX_ERROR);
        return;
    }

    /* 若设置了延迟，则将读事件添加到定时器事件机制中 */
    if (timer) {

        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

        timer *= 1000;

        if (timer > clcf->lingering_timeout) {
            timer = clcf->lingering_timeout;
        }

        ngx_add_timer(rev, timer);
    }
}
```
ngx_http_read_discarded_request_body 函数执行流程：
若待丢弃请求包体长度 content_length_n 为0，表示已经接收到完整请求包体，并成功将其丢弃，则此时，设置读事件的回调方法为ngx_http_block_reading（不进行任何操作），同时返回NGX_OK，表示已成功丢弃完整请求包体；
若需要继续丢弃请求包体数据，且此时，连接上套接字缓冲区没有可读数据，即读事件未准备就绪，则返回 NGX_AGAIN，表示需要等待读事件再次被触发时继续读取请求包体并丢弃；
调用函数 recv 读取请求包体数据，根据不同返回值 n，进行不同的判断：
若返回值 n = NGX_AGAIN，表示读取的请求包体依旧不完整，需要等待下次读事件被触发，继续读取请求包体数据；
若 n = NGX_ERROR 或 n = 0，表示客户端主动关闭当前连接，则不需要读取请求包体，即直接返回 NGX_OK，表示结束丢弃包体动作；
若返回值 n = NGX_OK，则表示读取请求包体成功，此时调用函数ngx_http_discard_request_body_filter 将已经读取的请求包体丢弃，并更新content_length_n 的值；根据content_length_n 的值进行判断是否继续读取请求包体数据（此时又回到步骤1，因此是一个for 循环），直到读取到完整的请求包体，并将其丢弃，才结束for 循环，并从该函数返回；
函数 ngx_http_read_discarded_request_body 在文件src/http/ngx_http_request_body.c 中定义如下：
```
/* 读取请求包体，并将其丢弃 */
static ngx_int_t
ngx_http_read_discarded_request_body(ngx_http_request_t *r)
{
    size_t     size;
    ssize_t    n;
    ngx_int_t  rc;
    ngx_buf_t  b;
    u_char     buffer[NGX_HTTP_DISCARD_BUFFER_SIZE];

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http read discarded body");

    ngx_memzero(&b, sizeof(ngx_buf_t));

    b.temporary = 1;

    for ( ;; ) {
        /* 若待丢弃的请求包体大小content_length_n 为0，表示不需要接收请求包体 */
        if (r->headers_in.content_length_n == 0) {
            /* 重新设置读事件的回调方法，其实该回调方法不进行任何操作 */
            r->read_event_handler = ngx_http_block_reading;
            return NGX_OK;
        }

        /* 若当前连接的读事件未准备就绪，则不能读取数据，即返回NGX_AGAIN */
        if (!r->connection->read->ready) {
            return NGX_AGAIN;
        }

        /* 若需要读取请求包体数据，计算需要读取请求包体的大小size */
        size = (size_t) ngx_min(r->headers_in.content_length_n,
                                NGX_HTTP_DISCARD_BUFFER_SIZE);

        /* 从连接套接字缓冲区读取请求包体数据 */
        n = r->connection->recv(r->connection, buffer, size);

        if (n == NGX_ERROR) {
            r->connection->error = 1;
            return NGX_OK;
        }

        /* 若读取的请求包体数据不完整，则继续读取 */
        if (n == NGX_AGAIN) {
            return NGX_AGAIN;
        }

        /* 若n=0或n=NGX_ERROR表示读取失败，即该连接已关闭，则不需要丢弃包体 */
        if (n == 0) {
            return NGX_OK;
        }

        /* 若返回n=NGX_OK ，表示读取到完整的请求包体，则将其丢弃 */
        b.pos = buffer;
        b.last = buffer + n;

        /* 将读取的完整请求包体丢弃 */
        rc = ngx_http_discard_request_body_filter(r, &b);

        if (rc != NGX_OK) {
            return rc;
        }
    }
}
```
发送 HTTP 响应报文

HTTP 的响应报文由 Filter 模块处理并发送，Filter 模块包括过滤头部（Header Filter）和过滤包体（Body Filter），Filter 模块过滤头部处理 HTTP 响应头部（HTTP headers），Filter 包体处理HTTP 响应包体（response content）。HTTP 响应报文发送的过程需要经过Nginx 的过滤链，所谓的过滤链就是由多个过滤模块组成有序的过滤链表，每个链表元素就是对应过滤模块的处理方法。在HTTP 框架中，定义了过滤链表表头（即链表的第一个元素，也是处理方法）如下：
extern ngx_http_output_header_filter_pt  ngx_http_top_header_filter;/* 发送响应头部 */
extern ngx_http_output_body_filter_pt  ngx_http_top_body_filter;/* 发送响应包体 */
其中，ngx_http_output_header_filter_pt 和 ngx_http_output_body_filter_pt 是函数指针，定义如下：
typedef ngx_int_t (*ngx_http_output_header_filter_pt) (ngx_http_request_t *r);/* 发送响应头部 */
typedef ngx_int_t (*ngx_http_output_body_filter_pt) (ngx_http_request_t *r, ngx_chain_t *chain);/* 发送响应包体 */
参数 r 是当前的请求，chain 是待发送的HTTP 响应包体；上面提到的只有过滤链表的表头，那么使用什么把所有过滤模块连接起来呢？该工作由下面定义完成，即：
static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt  ngx_http_next_body_filter;
这样就可以遍历整个过滤链表，把 HTTP 响应报文发送出去，按照过滤链表的顺序，调用链表元素的回调方法可能会对响应报文数据进行检测、截取、新增、修改 或 删除等操作，即FIlter 模块可以对响应报文进行修改。但是必须注意的是只有最后一个链表元素才会真正的发送响应报文。
发送 HTTP 响应头部

HTTP 响应状态行、响应头部由函数 ngx_http_send_header 发送，该发送函数的执行过程中会遍历过滤链表，该过滤链表的过滤模块是那些对 HTTP 响应头部感兴趣的过滤模块组成，ngx_http_send_header 函数按照过滤链表的顺序依次处理响应头部，直到最后一个链表元素处理响应头部并把该响应头部发送给客户端。ngx_http_send_header 函数定义在文件src/http/ngx_http_core_module.c 中如下：
```
/* 发送 HTTP 响应头部 */
ngx_int_t
ngx_http_send_header(ngx_http_request_t *r)
{
    if (r->header_sent) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "header already sent");
        return NGX_ERROR;
    }

    if (r->err_status) {
        r->headers_out.status = r->err_status;
        r->headers_out.status_line.len = 0;
    }

    return ngx_http_top_header_filter(r);
}
```
从函数的实现过程中我们可以知道，该函数调用 ngx_http_top_header_filter 方法开始顺序遍历过滤链表的每一个元素处理方法，直到最后一个把响应头部发送出去为止。在Nginx中，过滤链表的顺序如下：
 +----------------------------+
  |ngx_http_not_modified_filter|
  +----------+-----------------+
             |
             v
  +----------+------------+
  |ngx_http_headers_filter|
  +----------+------------+
             |
             v
  +----------+-----------+
  |ngx_http_userid_filter|
  +----------+-----------+
             |
             v
  +----------+-------------------+
  |ngx_http_charset_header_filter|
  +----------+-------------------+
             |
             v
  +----------+---------------+
  |ngx_http_ssi_header_filter|
  +----------+---------------+
             |
             v
  +----------+----------------+
  |ngx_http_gzip_header_filter|
  +----------+----------------+
             |
             v
  +----------+-----------------+
  |ngx_http_range_header_filter|
  +----------+-----------------+
             |
             v
  +----------+-------------------+
  |ngx_http_chunked_header_filter|
  +----------+-------------------+
             |
             v
  +----------+-----------+
  |ngx_http_header_filter|
  +----------------------+
根据发送响应头部的过滤链表顺序可以知道，除了最后一个模块是真正发送响应头部给客户端之外，其他模块都只是对响应头部进行修改，最后一个过来模块是ngx_http_header_filter_module，该模块提供的处理方法是ngx_http_header_filter 根据请求结构体ngx_http_request_t 中的 header_out 成员序列化字符流，并发送序列化之后的响应头部；
ngx_http_header_filter_module 模块的定义如下：
ngx_module_t  ngx_http_header_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_header_filter_module_ctx,    /* module context */
    NULL,                                  /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

从该模块的定义中可以知道，该模块只调用上下文结构 ngx_http_header_filter_module_ctx，该上下文结构定义如下：
static ngx_http_module_t  ngx_http_header_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_header_filter_init,           /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL,                                  /* merge location configuration */
};

上下文结构指定了 postconfiguration 的方法为 ngx_http_header_filter_init，该方法定义如下：
/* 初始化ngx_http_header_filter_module模块 */
static ngx_int_t
ngx_http_header_filter_init(ngx_conf_t *cf)
{
    /* 调用ngx_http_header_filter方法发送响应头部 */
    ngx_http_top_header_filter = ngx_http_header_filter;

    return NGX_OK;
}

最终该模块由方法  ngx_http_header_filter 执行即发送HTTP 响应头部，下面对该方法进行分析；
ngx_http_header_filter 函数执行流程：
首先检查当前请求 ngx_http_request_t 结构的header_sent 标志位，若该标志位为1，则表示已经发送过响应头部，因此，无需重复发送，直接返回NGX_OK 结束该函数；
若之前未发送过响应头部（即 headr_sent 标志位为0），此时，准备发送响应头部，并设置header_sent 标志位为1（防止重复发送），表示正要发送响应头部，同时检查当前请求是否为原始请求，若不是原始请求（即为子请求），则不需要发送响应头部返回 NGX_OK，因为子请求不存在响应头部概念。继而检查HTTP 协议版本，若HTTP 协议版本小于  1.0（即不支持请求头部，也就没有所谓的响应头部）直接返回NGX_OK，若是原始请求且HTTP 协议版本不小于1.0版本，则准备发送响应头部；
根据 HTTP 响应报文的状态行、响应头部将字符串序列化为发送响应头部所需的字节数len，方便下面分配缓冲区空间存在待发送的响应头部；
根据前一步骤计算的 len 值在当前请求内存池中分配用于存储响应头部的字符流缓冲区b，并将响应报文的状态行、响应头部按照HTTP 规范序列化地复制到刚分配的缓冲区b 中；
将待发送响应头部的缓冲区 b 挂载到链表缓冲区 out.buf 中；挂载的目的是：当响应头部不能一次性发送完毕时，ngx_http_header_filter 方法会返回NGX_AGAIN，表示发送的响应头部不完整，则把剩余的响应头部数据保存在out 链表缓冲区中，以便调用ngx_http_filter_request 时，再次调用 HTTP 框架将 out 链表缓冲区的剩余响应头部字符流发送出去；
调用 ngx_http_writer_filter 方法将out 链表缓冲区的响应头部发送出去，但是不能保证一次性发送完毕；
函数 ngx_http_header_filter 在文件src/http/ngx_http_header_filter_module.c 中定义如下：
```
/* 发送HTTP响应头部 */
static ngx_int_t
ngx_http_header_filter(ngx_http_request_t *r)
{
    u_char                    *p;
    size_t                     len;
    ngx_str_t                  host, *status_line;
    ngx_buf_t                 *b;
    ngx_uint_t                 status, i, port;
    ngx_chain_t                out;
    ngx_list_part_t           *part;
    ngx_table_elt_t           *header;
    ngx_connection_t          *c;
    ngx_http_core_loc_conf_t  *clcf;
    ngx_http_core_srv_conf_t  *cscf;
    struct sockaddr_in        *sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6       *sin6;
#endif
    u_char                     addr[NGX_SOCKADDR_STRLEN];

    /*
     * 检查当前请求结构的header_sent标志位，若该标志位为1，
     * 表示已经发送HTTP请求响应，则无需再发送，此时返回NGX_OK；
     */
    if (r->header_sent) {
        return NGX_OK;
    }

    /* 若之前未发送HTTP请求响应，则现在准备发送，并设置header_sent标志位 */
    r->header_sent = 1;

    /* 当前请求不是原始请求，则返回NGX_OK */
    if (r != r->main) {
        return NGX_OK;
    }

    /*
     * 若HTTP版本为小于1.0 则直接返回NGX_OK；
     * 因为这些版本不支持请求头部，所有就没有响应头部；
     */
    if (r->http_version < NGX_HTTP_VERSION_10) {
        return NGX_OK;
    }

    if (r->method == NGX_HTTP_HEAD) {
        r->header_only = 1;
    }

    if (r->headers_out.last_modified_time != -1) {
        if (r->headers_out.status != NGX_HTTP_OK
            && r->headers_out.status != NGX_HTTP_PARTIAL_CONTENT
            && r->headers_out.status != NGX_HTTP_NOT_MODIFIED)
        {
            r->headers_out.last_modified_time = -1;
            r->headers_out.last_modified = NULL;
        }
    }

    /* 以下是根据HTTP响应报文的状态行、响应头部字符串序列化为所需的字节数len */
    len = sizeof("HTTP/1.x ") - 1 + sizeof(CRLF) - 1
          /* the end of the header */
          + sizeof(CRLF) - 1;

    /* status line */

    if (r->headers_out.status_line.len) {
        len += r->headers_out.status_line.len;
        status_line = &r->headers_out.status_line;

     ...
     ...

    /* 分配用于存储响应头部字符流缓冲区 */
    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NGX_ERROR;
    }

    /* 将响应报文的状态行、响应头部按照HTTP规范序列化地复制到刚分配的缓冲区b中 */
    /* "HTTP/1.x " */
    b->last = ngx_cpymem(b->last, "HTTP/1.1 ", sizeof("HTTP/1.x ") - 1);

    /* status line */
    if (status_line) {
        b->last = ngx_copy(b->last, status_line->data, status_line->len);

    } else {
        b->last = ngx_sprintf(b->last, "%03ui ", status);
    }

    ...
    ...

    /*
     * 将待发送的响应头部挂载到out链表缓冲区中，
     * 挂载的目的是：当响应头部不能一次性发送完成时，
     * ngx_http_header_filter方法返回NGX_AGAIN，表示发送的响应头部不完整，
     * 则把剩余的响应头部保存在out链表中，以便调用ngx_http_finalize_request时，
     * 再次调用HTTP框架将out链表中剩余的响应头部字符流继续发送；
     */
    out.buf = b;
    out.next = NULL;

    /*
     * 调用方法ngx_http_write_filter将响应头部字符流发送出去；
     * 所有实际发送响应头部数据的由ngx_http_write_filter方法实现；
     */
    return ngx_http_write_filter(r, &out);
}
```
发送 HTTP 响应包体

HTTP 响应包体由函数 ngx_http_output_filter 发送，该发送函数的执行过程中会遍历过滤链表，该过滤链表的过滤模块是那些对 HTTP 响应包体感兴趣的过滤模块组成，ngx_http_output_filter 函数按照过滤链表的顺序依次处理响应包体，直到最后一个链表元素处理响应包体并把该响应包体发送给客户端。ngx_http_output_filter 函数定义在文件 src/http/ngx_http_core_module.c 中如下：
```
/* 发送HTTP 响应包体 */
ngx_int_t
ngx_http_output_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_int_t          rc;
    ngx_connection_t  *c;

    c = r->connection;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http output filter \"%V?%V\"", &r->uri, &r->args);

    rc = ngx_http_top_body_filter(r, in);

    if (rc == NGX_ERROR) {
        /* NGX_ERROR may be returned by any filter */
        c->error = 1;
    }

    return rc;
}
```
从函数的实现过程中我们可以知道，该函数调用 ngx_http_top_body_filter 方法开始顺序遍历过滤链表的每一个元素处理方法，直到最后一个把响应包体发送出去为止。在Nginx 中，过滤链表的顺序如下：
  +--------------------------+
  |ngx_http_range_body_filter|
  +----------+---------------+
             |
             v
  +----------+---------+
  |ngx_http_copy_filter|
  +----------+---------+
             |
             v
  +----------+-----------------+
  |ngx_http_charset_body_filter|
  +----------+-----------------+
             |
             v
  +----------+-------------+
  |ngx_http_ssi_body_filter|
  +----------+-------------+
             |
             v
  +----------+-------------+
  |ngx_http_postpone_filter|
  +----------+-------------+
             |
             v
  +----------+--------------+
  |ngx_http_gzip_body_filter|
  +----------+--------------+
             |
             v
  +----------+-----------------+
  |ngx_http_chunked_body_filter|
  +----------+-----------------+
             |
             v
  +---------------------+
  |ngx_http_write_filter|
  +---------------------+
根据发送响应包体的过滤链表顺序可以知道，除了最后一个模块是真正发送响应包体给客户端之外，其他模块都只是对响应包体进行修改，最后一个过来模块是ngx_http_write_filter_module，该模块提供的处理方法是ngx_http_write_filter；
ngx_http_write_filter_module 模块的定义如下：
ngx_module_t  ngx_http_write_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_write_filter_module_ctx,     /* module context */
    NULL,                                  /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

该模块的上下文结构 ngx_http_write_filter_module_ctx 定义如下：
static ngx_http_module_t  ngx_http_write_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_write_filter_init,            /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL,                                  /* merge location configuration */
};

上下文结构中只调用 ngx_http_write_filter_init 方法，该方法定义如下：
/* 初始化模块 */
static ngx_int_t
ngx_http_write_filter_init(ngx_conf_t *cf)
{
    /* 调用模块的回调方法 */
    ngx_http_top_body_filter = ngx_http_write_filter;

    return NGX_OK;
}

该模块最终调用 ngx_http_write_filter 方法发送HTTP 响应包体，该方法的实现如下分析；
ngx_http_writer_filter 函数执行流程：
检查当前连接的错误标志位 error，若该标志位为 1，表示当前请求出粗，则返回 NGX_ERROR 结束该函数，否则继续；
遍历当前请求 ngx_http_request_t 结构体中的链表缓冲区成员out，计算剩余响应报文的长度size。因为当响应报文一次性不能发送完毕时，会把剩余的响应报文保存在out 中，相对于本次待发送的响应报文 in (即是该函数所传入的参数in )来说，out 链表缓冲区保存的是前一次剩余的响应报文；
将本次待发送的响应报文的缓冲区 in 添加到 out 链表缓冲区的尾部，并计算待发送响应报文的总长度 size；
若缓冲区 ngx_buf_t 块的 last_buf (即 last)、flush 标志位为0，则表示待发送的out 链表缓冲区没有一个是需要立刻发送响应报文，并且本次待发送的in 不为空，且待发送的响应报文数据总长度 size 小于postpone_output 参数（该参数由nginx.conf配置文件中设置），则不需要发送响应报文，即返回NGX_OK 结束该函数；
若需要发送响应报文，则检查当前连接上写事件的 delayed 标志位，若为1，表示发送响应超速，则需要在epoll 事件机制中减速，所有相当于延迟发送响应报文，则返回NGX_AGIAN；
若不需要延迟发送响应报文，检查当前请求的限速标志位 limit_rate，若该标志位设置为大于0，表示当前发送响应报文的速度不能超过limit_rate 值；
根据限速值 r->limit_rate、当前客户开始接收响应的时间r->start_sec、在当前连接上已发送响应的长度c->sent、和limit_after 值计算本次可以发送的字节数limit，若limit 值不大于0，表示当前连接上发送响应的速度超过limit_rate 限速值，即本次不可以发送响应，因此将写事件的delayed 标志位设置为1，把写事件添加到定时器机制，并设置当前连接ngx_connection_t 结构体中的成员buffered 为NGX_HTTP_WRITE_BUFFERED（即可写状态），同时返回NGX_AGAIN，表示链表缓冲区out 还保存着剩余待发送的响应报文；
若 limit 值大于 0，则根据 limit 值、配置项参数 sendfile_max_chunk 和待发送字节数 size 来计算本次发送响应的长度(即三者中的最小值)；
根据前一步骤计算的可发送响应的长度，再次检查 limit_rate 标志位，若limit_rate 还是为1，表示继续需要限速检查。再按照前面的计算方法判断是否超过限速值limit_rate，若超过该限速值，则需再次把写事件添加到定时器机制中，标志位delayed 设置为1；
若不会超过限速值，则发送响应，并重新调整链表缓冲区 out 的情况，把已发送响应数据的缓冲区进行回收内存；
继续检查链表缓冲区 out 是否还存在数据，若存在数据，则表示未发送完毕，返回NGX_AGAIN，表示等待下次HTTP 框架被调用发送out 缓冲区剩余的响应数据；若不存在数据，则表示成功发送完整的响应数据，并返回NGX_OK；
函数 ngx_http_write_filter 在文件 src/http/ngx_http_write_filter_module.c 中定义如下：
/* 发送响应报文数据 */

/* 参数r是对应的请求，in是保存本次待发送数据的链表缓冲区 */
ngx_int_t
ngx_http_write_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    off_t                      size, sent, nsent, limit;
    ngx_uint_t                 last, flush;
    ngx_msec_t                 delay;
    ngx_chain_t               *cl, *ln, **ll, *chain;
    ngx_connection_t          *c;
    ngx_http_core_loc_conf_t  *clcf;

    /* 获取当前请求所对应的连接 */
    c = r->connection;

    /*
     * 检查当前连接的错误标志位error，若该标志位为1，
     * 表示当前请求出错，返回NGX_ERROR；
     */
    if (c->error) {
        return NGX_ERROR;
    }

    size = 0;
    flush = 0;
    last = 0;
    ll = &r->out;

    /* find the size, the flush point and the last link of the saved chain */

    /*
     * 遍历当前请求out链表缓冲区，计算剩余响应报文的长度；
     * 因为当响应报文一次性不能发送完成时，会把剩余的响应报文保存在out中，
     * 相对于本次发送的响应报文数据in来说（即该方法所传入的参数in），
     * out链表缓冲区保存的是前一次剩余的响应报文；
     */
    for (cl = r->out; cl; cl = cl->next) {
        ll = &cl->next;

        ngx_log_debug7(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "write old buf t:%d f:%d %p, pos %p, size: %z "
                       "file: %O, size: %z",
                       cl->buf->temporary, cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);

#if 1
        ...
#endif

        size += ngx_buf_size(cl->buf);

        if (cl->buf->flush || cl->buf->recycled) {
            flush = 1;
        }

        if (cl->buf->last_buf) {
            last = 1;
        }
    }

    /* add the new chain to the existent one */

    /*
     * 将本次待发送的响应报文的缓冲区in添加到out链表缓冲区的尾部，
     * 并计算待发送响应报文总的长度size；
     */
    for (ln = in; ln; ln = ln->next) {
        cl = ngx_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        cl->buf = ln->buf;
        *ll = cl;/* 由上面可知 ll=&r->out */
        ll = &cl->next;

        ngx_log_debug7(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "write new buf t:%d f:%d %p, pos %p, size: %z "
                       "file: %O, size: %z",
                       cl->buf->temporary, cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);

#if 1
        ...
#endif

        size += ngx_buf_size(cl->buf);

        if (cl->buf->flush || cl->buf->recycled) {
            flush = 1;
        }

        if (cl->buf->last_buf) {
            last = 1;
        }
    }

    *ll = NULL;

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http write filter: l:%d f:%d s:%O", last, flush, size);

    /* 获取ngx_http_core_module模块的loc级别配置项结构体 */
    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    /*
     * avoid the output if there are no last buf, no flush point,
     * there are the incoming bufs and the size of all bufs
     * is smaller than "postpone_output" directive
     */

    /*
     * 若out链表最后一块缓冲区last为空，且没有强制性刷新flush链表缓冲区out，
     * 且当前有待发响应报文in，但是待发送响应报文总的长度size小于预设可发送条件值postpone_output,
     * 则本次不能发送响应报文，继续保存在out链表缓冲区中，以待下次才发送；
     * 其中postpone_output预设值我们可以在配置文件nginx.conf中设置；
     */
    if (!last && !flush && in && size < (off_t) clcf->postpone_output) {
        return NGX_OK;
    }

    /*
     * 检查当前连接上写事件的delayed标志位，
     * 若该标志位为1，表示需要延迟发送响应报文，
     * 因此，返回NGX_AGAIN，表示延迟发送；
     */
    if (c->write->delayed) {
        c->buffered |= NGX_HTTP_WRITE_BUFFERED;
        return NGX_AGAIN;
    }

    if (size == 0
        && !(c->buffered & NGX_LOWLEVEL_BUFFERED)
        && !(last && c->need_last_buf))
    {
        if (last || flush) {
            for (cl = r->out; cl; /* void */) {
                ln = cl;
                cl = cl->next;
                ngx_free_chain(r->pool, ln);
            }

            r->out = NULL;
            c->buffered &= ~NGX_HTTP_WRITE_BUFFERED;

            return NGX_OK;
        }

        ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                      "the http output chain is empty");

        ngx_debug_point();

        return NGX_ERROR;
    }

    /*
     * 检查当前请求的限速标志位limit_rate，
     * 若该标志位为大于0，表示发送响应报文的速度不能超过limit_rate指定的速度；
     */
    if (r->limit_rate) {
        if (r->limit_rate_after == 0) {
            r->limit_rate_after = clcf->limit_rate_after;
        }

        /* 计算发送速度是否超过限速值 */
        limit = (off_t) r->limit_rate * (ngx_time() - r->start_sec + 1)
                - (c->sent - r->limit_rate_after);

        /*
         * 若当前发送响应报文的速度超过限速值，则写事件标志位delayed设为1，
         * 并把该写事件添加到定时器机制中，并且将buffered设置为可写状态，
         * 返回NGX_AGAIN，表示链表缓冲区out还保存剩余待发送的响应报文；
         */
        if (limit <= 0) {
            c->write->delayed = 1;
            ngx_add_timer(c->write,
                          (ngx_msec_t) (- limit * 1000 / r->limit_rate + 1));

            c->buffered |= NGX_HTTP_WRITE_BUFFERED;

            return NGX_AGAIN;
        }

        if (clcf->sendfile_max_chunk
            && (off_t) clcf->sendfile_max_chunk < limit)
        {
            limit = clcf->sendfile_max_chunk;
        }

    } else {
        limit = clcf->sendfile_max_chunk;
    }

    /* 若不需要减速，或没有设置速度限制，则向客户端发送响应字符流 */
    sent = c->sent;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http write filter limit %O", limit);

    chain = c->send_chain(c, r->out, limit);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http write filter %p", chain);

    if (chain == NGX_CHAIN_ERROR) {
        c->error = 1;
        return NGX_ERROR;
    }

    /* 再次检查limit_rate标志位 */
    if (r->limit_rate) {

        nsent = c->sent;

        if (r->limit_rate_after) {

            sent -= r->limit_rate_after;
            if (sent < 0) {
                sent = 0;
            }

            nsent -= r->limit_rate_after;
            if (nsent < 0) {
                nsent = 0;
            }
        }

        /* 再次计算当前发送响应报文速度是否超过限制值 */
        delay = (ngx_msec_t) ((nsent - sent) * 1000 / r->limit_rate);

        /* 若超过，需要限速，并把写事件添加到定时器机制中 */
        if (delay > 0) {
            limit = 0;
            c->write->delayed = 1;
            ngx_add_timer(c->write, delay);
        }
    }

    if (limit
        && c->write->ready
        && c->sent - sent >= limit - (off_t) (2 * ngx_pagesize))
    {
        c->write->delayed = 1;
        ngx_add_timer(c->write, 1);
    }

    /* 重新调整链表缓冲区out的情况，把已发送数据的缓冲区内存回收 */
    for (cl = r->out; cl && cl != chain; /* void */) {
        ln = cl;
        cl = cl->next;
        ngx_free_chain(r->pool, ln);
    }

    /* 检查out链表缓冲区是否还有数据 */
    r->out = chain;

    /* 若还有数据，返回NGX_AGAIN，表示还存在待发送的响应报文数据 */
    if (chain) {
        c->buffered |= NGX_HTTP_WRITE_BUFFERED;
        return NGX_AGAIN;
    }

    c->buffered &= ~NGX_HTTP_WRITE_BUFFERED;

    if ((c->buffered & NGX_LOWLEVEL_BUFFERED) && r->postponed == NULL) {
        return NGX_AGAIN;
    }

    /* 若已发送全部数据则返回NGX_OK */
    return NGX_OK;
}

ngx_http_write 函数执行流程如下：
检查写事件的 timedout 标志位，若该标志位为 1（表示超时），进而判断属于哪种情况引起的超时（第一种：网络异常或客户端长时间不接收响应；第二种：由于响应发送速度超速，导致写事件被添加到定时器机制（注意一点：delayed 标志位此时是为1），有超速引起的超时，不算真正的响应发送超时）；
检查 delayed 标志位，若 delayed 为 0，表示由第一种情况引起的超时，即是真正的响应超时，此时设置timedout 标志位为1，并调用函数ngx_http_finalize_request 结束请求；
若 delayed 为 1，表示由第二种情况引起的超时，不算真正的响应超时，此时，把标志位 timedout、delayed 都设置为 0，继续检查写事件的 ready 标志位，若 ready 为 0，表示当前写事件未准备就绪（即不可写），因此，将写事件添加到定时器机制，注册到epoll 事件机制中，等待可写事件发送，返回return 结束该方法；
若写事件 timedout 为 0，且 delayed 为 0，且 ready 为 1，则调用函数 ngx_http_output_filter 发送响应；该函数的第二个参数为NULL，表示需要调用各个包体过滤模块处理链表缓冲区out 中剩余的响应，最后由ngx_http_write_filter 方法把响应发送出去；
函数 ngx_http_writer 在文件 src/http/ngx_http_request.c 中定义如下：
static void
ngx_http_writer(ngx_http_request_t *r)
{
    int                        rc;
    ngx_event_t               *wev;
    ngx_connection_t          *c;
    ngx_http_core_loc_conf_t  *clcf;

    /* 获取当前请求的连接 */
    c = r->connection;
    /* 获取连接上的写事件 */
    wev = c->write;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, wev->log, 0,
                   "http writer handler: \"%V?%V\"", &r->uri, &r->args);

    /* 获取ngx_http_core_module模块的loc级别配置项结构 */
    clcf = ngx_http_get_module_loc_conf(r->main, ngx_http_core_module);

    /*
     * 写事件超时有两种可能：
     * 1、由于网络异常或客户端长时间不接收响应，导致真实的发送响应超时；
     * 2、由于响应发送速度超过了请求的限速值limit_rate，导致写事件被添加到定时器机制中，
     *    这是由超速引起的，并不是真正的响应发送超时；注意：写事件被添加到定时器机制时，delayed标志位设置为1；
     */

    /* 检查写事件是否超时，若超时(即timedout为1)，进而判断属于哪种情况引起的超时 */
    if (wev->timedout) {
        /*
         * 若是响应真的超时，即网络异常或客户端长时间未接收响应引起的超时；
         * 则将timedout标志位设置为1，并调用ngx_http_finalize_request结束请求；
         * 并return返回结束当前方法；
         */
        if (!wev->delayed) {
            ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                          "client timed out");
            c->timedout = 1;

            ngx_http_finalize_request(r, NGX_HTTP_REQUEST_TIME_OUT);
            return;
        }

        /*
         * 若是由超速发送响应引起的超时，则将timedout、delayed标志位都设为0；
         * 再继续检查写事件的ready标志位；
         */
        wev->timedout = 0;
        wev->delayed = 0;

        /*
         * 检查写事件的ready标志位，若写事件未准备就绪(ready=0)，即表示当前写事件不可写，
         * 则将写事件添加到定时器机制中，同时将写事件注册到epoll事件机制中，等待可写事件发生；
         * 并return结束当前方法；
         */
        if (!wev->ready) {
            ngx_add_timer(wev, clcf->send_timeout);

            if (ngx_handle_write_event(wev, clcf->send_lowat) != NGX_OK) {
                ngx_http_close_request(r, 0);
            }

            return;
        }

    }

    /* 当timedout为0，但是delayed为1或是aio，则将写事件注册到epoll事件机制中，并return返回 */
    if (wev->delayed || r->aio) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, wev->log, 0,
                       "http writer delayed");

        if (ngx_handle_write_event(wev, clcf->send_lowat) != NGX_OK) {
            ngx_http_close_request(r, 0);
        }

        return;
    }

    /* 若写事件timedout为0，且delayed为0，且ready为1，则调用ngx_http_output_filter 发送响应报文 */
    rc = ngx_http_output_filter(r, NULL);

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http writer output filter: %d, \"%V?%V\"",
                   rc, &r->uri, &r->args);

    /* 若发送响应错误，则调用ngx_http_finalize_request结束请求，并return返回 */
    if (rc == NGX_ERROR) {
        ngx_http_finalize_request(r, rc);
        return;
    }

    /*
     * 若成功发送响应，则检查当前请求的out链表缓冲区是否存在剩余待发送的响应报文，
     * 若存在剩余待发送响应，又因为此时写事件不可写，则将其添加到定时器机制，注册到epoll事件机制中，
     * 等待可写事件的发生生；*/
    if (r->buffered || r->postponed || (r == r->main && c->buffered)) {

        if (!wev->delayed) {
            ngx_add_timer(wev, clcf->send_timeout);
        }

        if (ngx_handle_write_event(wev, clcf->send_lowat) != NGX_OK) {
            ngx_http_close_request(r, 0);
        }

        return;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, wev->log, 0,
                   "http writer done: \"%V?%V\"", &r->uri, &r->args);

    /*
     * 若当前out链表缓冲区不存在未发送的响应数据，则表示已成功发送完整的响应数据，
     * 此时，重新设置写事件的回调方法为ngx_http_request_empty_handler即不进行任何操作；
     */
    r->write_event_handler = ngx_http_request_empty_handler;

    /* 最终调用ngx_http_finalize_request结束请求 */
    ngx_http_finalize_request(r, rc);
}

总结：真正发送响应的是 ngx_http_write_filter 函数，但是该函数不能保证一次性把响应发送完毕，若发送不完毕，把剩余的响应保存在out 链表缓冲区中，继而调用ngx_http_writer 把剩余的响应发送出去，函数ngx_http_writer 最终调用的是ngx_http_output_filter 函数发送响应，但是要知道的是ngx_http_output_filter 函数是需要调用个包体过滤模块来处理剩余响应的out 链表缓冲区，并由最后一个过滤模块 ngx_http_write_filter_module 调用ngx_http_write_filter 方法将响应发送出去；因此，我们可知道，真正发送响应的函数是ngx_http_write_filter；
关闭连接请求

当一个动作结束时，会根据引用计数判断是否结束其处理的请求，以下是有关关闭请求的函数；以下函数均在在文件 src/http/ngx_http_request.c 中定义如下；
ngx_http_finalize_request 函数执行流程：
若所传入的参数 rc  =  NGX_DONE，则直接调用ngx_http_finalize_connection 函数结束连接，并return 退出当前函数；
若参数 rc = NGX_DECLINED，表示需要按照11 个HTTP 阶段继续处理，此时，设置r->content_handler = NULL（为了让ngx_http_core_content_phase 方法可以继续调用NGX_HTTP_CONTENT_PHASE 阶段的其他处理方法），并设置写事件的回调方法为ngx_http_core_run_phases，最后调用ngx_http_core_run_phases 方法处理请求，return 从当前函数返回；
若  rc != NGX_DONE 且 rc != NGX_DECLINED，检查当前请求是否为子请求：
若当前请求是子请求，则调用 post_subrequest 的回调方法handler；
若不是子请求则继续执行以下程序；
若 rc 为 NGX_ERROR、NGX_HTTP_REQUEST_TIME_OUT、NGX_HTTP_CLIENT_CLOSED_REQUEST，或当前连接的错误码标志位c->error为1，则调用ngx_http_terminate_request 强制关闭请求，return 从当前函数返回；
若 rc 为 NGX_HTTP_CREATED、NGX_HTTP_NO_CONTENT，或rc 不小于NGX_HTTP_SPECIAL_RESPONSE，接着检查当前请求是否为原始请求，若是原始请求，则检查读、写事件的timer_set 标志位，若 timer_set 为1，将读、写事件从定时器机制中移除，重新设置当前连接的读、写事件的回调方法都为ngx_http_request_handler，并调用ngx_http_finalize_request，此时应该注意的是ngx_http_finalize_request 函数的第二个参数是ngx_http_special_response_handler(r, rc)函数的返回值，ngx_http_special_response_handler(r, rc) 函数根据参数rc 构造完整的HTTP 响应，根据ngx_http_special_response_handler 函数的返回值调用ngx_http_finalize_request 方法结束请求。return 从当前函数返回；
若参数 rc 不是以上步骤所描述的值，检查当前请求是否为原始请求：
若当前请求不是原始请求，
若当前请求是原始请求，检查当前请求的 buffered、postponed、blocked 标志位 或当前连接的buffered 标志位：
若这些标志位有一个是 1，则调用 ngx_http_set_write_handler 函数（该函数的功能就是设置当前请求写事件的回调方法为 ngx_http_writer 发送 out 链表缓冲区的剩余响应，若写事件未准备就绪，则将写事件添加到定时器机制，注册到epoll 事件机制中，最终返回NGX_OK），并return 返回当前函数；
若这些标志位都不为 1，则检查读、写事件的 timer_set 标志位，若 timer_set 标志位为1，则将读、写事件从定时器机制中移除，最后调用ngx_http_finalize_connection 释放请求，并关闭连接；
/* 结束请求 */
void
ngx_http_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_connection_t          *c;
    ngx_http_request_t        *pr;
    ngx_http_core_loc_conf_t  *clcf;

    c = r->connection;

    ngx_log_debug5(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http finalize request: %d, \"%V?%V\" a:%d, c:%d",
                   rc, &r->uri, &r->args, r == c->data, r->main->count);

    /* 若传入的参数rc=NGX_DONE，则直接调用ngx_http_finalize_connection方法 */
    if (rc == NGX_DONE) {
        ngx_http_finalize_connection(r);
        return;
    }

    if (rc == NGX_OK && r->filter_finalize) {
        c->error = 1;
    }

    /*
     * 若传入的参数rc=NGX_DECLINED，则表示需按照11个HTTP阶段继续处理；
     * 此时，写事件调用ngx_http_core_run_phases；
     */
    if (rc == NGX_DECLINED) {
        r->content_handler = NULL;
        r->write_event_handler = ngx_http_core_run_phases;
        ngx_http_core_run_phases(r);
        return;
    }

    /* 若传入的参数rc != NGX_DONE 且 rc != NGX_DECLINED，则执行以下程序 */

    /*
     * 若当前处理的请求是子请求，且post_subrequest标志位为1，
     * 则调用post_subrequest的handler回调方法；
     */
    if (r != r->main && r->post_subrequest) {
        rc = r->post_subrequest->handler(r, r->post_subrequest->data, rc);
    }

    /* 若处理的当前请求不是子请求，则执行以下程序 */

    /* 若rc是以下这些值，或error标志位为1，则调用ngx_http_terminate_request方法强制关闭请求 */
    if (rc == NGX_ERROR
        || rc == NGX_HTTP_REQUEST_TIME_OUT
        || rc == NGX_HTTP_CLIENT_CLOSED_REQUEST
        || c->error)
    {
        if (ngx_http_post_action(r) == NGX_OK) {
            return;
        }

        if (r->main->blocked) {
            r->write_event_handler = ngx_http_request_finalizer;
        }

        ngx_http_terminate_request(r, rc);
        return;
    }

    /*
     * 若rc为以下值，表示请求的动作是上传文件，
     * 或HTTP模块需要HTTP框架构造并发送响应码不小于300的特殊响应；
     * 则首先检查当前请求是否为原始请求，若不是则调用ngx_http_terminate_request强制关闭请求，
     * 若是原始请求，则将读、写事件从定时器机制中移除；
     * 并重新设置读、写事件的回调方法为ngx_http_request_handler,
     * 最后调用ngx_http_finalize_request关闭请求（指定特定的rc参数）；
     */
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE
        || rc == NGX_HTTP_CREATED
        || rc == NGX_HTTP_NO_CONTENT)
    {
        if (rc == NGX_HTTP_CLOSE) {
            ngx_http_terminate_request(r, rc);
            return;
        }

        if (r == r->main) {
            if (c->read->timer_set) {
                ngx_del_timer(c->read);
            }

            if (c->write->timer_set) {
                ngx_del_timer(c->write);
            }
        }

        c->read->handler = ngx_http_request_handler;
        c->write->handler = ngx_http_request_handler;

        ngx_http_finalize_request(r, ngx_http_special_response_handler(r, rc));
        return;
    }

    /* 若rc不是以上的值，则执行以下程序 */

    /* 再次检查当前请求是否为原始请求 */
    if (r != r->main) {

        /*
         * 若当前请求不是原始请求，即当前请求是子请求；
         * 若子请求的buffered 或 postponed 标志位为1，
         * 则调用 ngx_http_set_write_handler;
         */
        if (r->buffered || r->postponed) {

            if (ngx_http_set_write_handler(r) != NGX_OK) {
                ngx_http_terminate_request(r, 0);
            }

            return;
        }

        /*
         * 若子请求的buffered且postponed标志位都为0，则找到当前子请求的父亲请求；
         */
        pr = r->parent;

        /*
         * 将父亲请求放置在ngx_http_posted_request_t结构体中，
         * 并将该结构体添加到原始请求的posted_requests链表中；
         */
        if (r->buffered || r->postponed) {

            if (ngx_http_set_write_handler(r) != NGX_OK) {
                ngx_http_terminate_request(r, 0);
            }
        if (r == c->data) {

            r->main->count--;
            r->main->subrequests++;

            if (!r->logged) {

                clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

                if (clcf->log_subrequest) {
                    ngx_http_log_request(r);
                }

                r->logged = 1;

            } else {
                ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                              "subrequest: \"%V?%V\" logged again",
                              &r->uri, &r->args);
            }

            r->done = 1;

            if (pr->postponed && pr->postponed->request == r) {
                pr->postponed = pr->postponed->next;
            }

            c->data = pr;

        } else {

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                           "http finalize non-active request: \"%V?%V\"",
                           &r->uri, &r->args);

            r->write_event_handler = ngx_http_request_finalizer;

            if (r->waited) {
                r->done = 1;
            }
        }

        if (ngx_http_post_request(pr, NULL) != NGX_OK) {
            r->main->count++;
            ngx_http_terminate_request(r, 0);
            return;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http wake parent request: \"%V?%V\"",
                       &pr->uri, &pr->args);

        return;
    }

    /* 若当前请求是原始请求 */

    /*
     * 若r->buffered或c->buffered 或 r->postponed 或 r->blocked 标志位为1；
     * 则调用ngx_http_set_write_handler方法；
     */
    if (r->buffered || c->buffered || r->postponed || r->blocked) {

        if (ngx_http_set_write_handler(r) != NGX_OK) {
            ngx_http_terminate_request(r, 0);
        }

        return;
    }

    if (r != c->data) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                      "http finalize non-active request: \"%V?%V\"",
                      &r->uri, &r->args);
        return;
    }

    r->done = 1;
    r->write_event_handler = ngx_http_request_empty_handler;

    if (!r->post_action) {
        r->request_complete = 1;
    }

    if (ngx_http_post_action(r) == NGX_OK) {
        return;
    }

    /*
     * 将读、写事件从定时器机制中移除；
     */
    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    if (c->write->timer_set) {
        c->write->delayed = 0;
        ngx_del_timer(c->write);
    }

    if (c->read->eof) {
        ngx_http_close_request(r, 0);
        return;
    }

    /* 关闭连接，并结束请求 */
    ngx_http_finalize_connection(r);
}

ngx_http_set_write_handler 函数执行流程：
设置当前请求的读事件回调方法为：ngx_httpp_discarded_request_body_handler（丢弃包体） 或ngx_http_test_reading；
设置当前请求的写事件回调方法为 ngx_http_writer（发送out 链表缓冲区剩余的响应）；
若当前写事件准备就绪（即 ready 和 delayed 标志位为 1）开始限速的发送 out 链表缓冲区中的剩余响应；
若当前写事件未准备就绪，则将写事件添加到定时器机制，注册到 epoll 事件机制中；
static ngx_int_t
ngx_http_set_write_handler(ngx_http_request_t *r)
{
    ngx_event_t               *wev;
    ngx_http_core_loc_conf_t  *clcf;

    r->http_state = NGX_HTTP_WRITING_REQUEST_STATE;

    /* 设置当前请求读事件的回调方法：丢弃包体或不进行任何操作 */
    r->read_event_handler = r->discard_body ?
                                ngx_http_discarded_request_body_handler:
                                ngx_http_test_reading;
    /* 设置写事件的回调方法为ngx_http_writer，即发送out链表缓冲区剩余的响应 */
    r->write_event_handler = ngx_http_writer;

#if (NGX_HTTP_SPDY)
    if (r->spdy_stream) {
        return NGX_OK;
    }
#endif

    wev = r->connection->write;

    /* 若写事件的ready标志位和delayed标志为都为1，则返回NGX_OK */
    if (wev->ready && wev->delayed) {
        return NGX_OK;
    }

    /*
     * 若写事件的ready标志位为0，或delayed标志位为0，则将写事件添加到定时器机制中；
     * 同时将写事件注册到epoll事件机制中；
     * 最后返回NGX_OK；
     */
    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    if (!wev->delayed) {
        ngx_add_timer(wev, clcf->send_timeout);
    }

    if (ngx_handle_write_event(wev, clcf->send_lowat) != NGX_OK) {
        ngx_http_close_request(r, 0);
        return NGX_ERROR;
    }

    return NGX_OK;
}

ngx_http_finalize_connection 函数的执行流程：
检查原始请求的引用计数，若原始请求的引用计数不为 1，则表示其他动作在操作该请求，检查当前请求的discard_body 标志位：
若 discard_body 标志位为 1，表示当前请求正在丢弃包体，把读事件的回调方法设为 ngx_http_discarded_request_body_handler 方法，并将读事件添加到定时器机制中（超时时间为lingering_timeout），最后调用ngx_http_close_request 关闭请求，并 return 从当前函数返回；
若 discard_body 标志位为 0，直接调用 ngx_http_close_request 关闭请求，并return 从当前函数返回；
若原始请求的引用计数为 1，检查当前请求的 keepalive 标志位：
若 keepalive 标志位为 1，则调用 ngx_http_set_keepalive方 法将当前连接设置为keepalive 状态，并return 从当前函数返回；
若 keepalive 标志位为 0，检查 lingering_close 标志位：
若 lingering_close 标志位为 1，则调用 ngx_http_set_lingering_close 延迟关闭请求，return 从当前函数返回；
若 lingering_close 标志位为 0，则调用 ngx_http_close_request 方法关闭请求；
/* 结束当前连接 */
static void
ngx_http_finalize_connection(ngx_http_request_t *r)
{
    ngx_http_core_loc_conf_t  *clcf;

#if (NGX_HTTP_SPDY)
    if (r->spdy_stream) {
        ngx_http_close_request(r, 0);
        return;
    }
#endif

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    /*
     * 检查原始请求的引用计数，若原始请求的引用计数不为1，表示有其他动作在操作该请求；
     */
    if (r->main->count != 1) {

        /*
         * 检查当前请求的discard_body标志位，若该标志位为1，表示当前请求正在丢弃包体；
         */
        if (r->discard_body) {
            /* 设置当前请求读事件的回调方法，并将读事件添加到定时器机制中 */
            r->read_event_handler = ngx_http_discarded_request_body_handler;
            ngx_add_timer(r->connection->read, clcf->lingering_timeout);

            if (r->lingering_time == 0) {
                r->lingering_time = ngx_time()
                                      + (time_t) (clcf->lingering_time / 1000);
            }
        }

        /* 关闭当前请求 */
        ngx_http_close_request(r, 0);
        return;
    }

    /* 若原始请求的引用计数为1，则执行以下程序 */

    /*
     * 若keepalive标志为1，表示只需要释放请求，但是当前连接需要复用；
     * 则调用ngx_http_set_keepalive 设置当前连接为keepalive状态；
     */
    if (!ngx_terminate
         && !ngx_exiting
         && r->keepalive
         && clcf->keepalive_timeout > 0)
    {
        ngx_http_set_keepalive(r);
        return;
    }

    /*
     * 若keepalive标志为0，但是lingering_close标志为1，表示需要延迟关闭连接；
     * 则调用ngx_http_set_lingering_close方法延迟关闭请求；
     */
    if (clcf->lingering_close == NGX_HTTP_LINGERING_ALWAYS
        || (clcf->lingering_close == NGX_HTTP_LINGERING_ON
            && (r->lingering_close
                || r->header_in->pos < r->header_in->last
                || r->connection->read->ready)))
    {
        ngx_http_set_lingering_close(r);
        return;
    }

    /* 若keepalive标志为0，且lingering_close标志也为0，则立刻关闭请求 */
    ngx_http_close_request(r, 0);
}

ngx_http_close_request 函数的执行流程：
将原始请求的引用计数 count 减 1，若此时引用计数 count 不为 0，或当前请求的 blocked 标志位为 1，即不需要正在关闭该请求，因为该请求有其他动作在操作，return 从当前函数返回；
若引用计数 count 为 0（表示没有其他动作操作当前请求），且 blocked 标志位为0（表示没有HTTP 模块会处理当前请求），因此，调用ngx_http_free_request 释放当前请求的结构体ngx_http_request_t，并调用函数ngx_http_close_connection 关闭当前连接；
/* 关闭当前请求 */
static void
ngx_http_close_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_connection_t  *c;

    r = r->main;
    c = r->connection;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http request count:%d blk:%d", r->count, r->blocked);

    if (r->count == 0) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0, "http request count is zero");
    }

    /* 将原始请求的引用计数减1 */
    r->count--;

    /*
     * 若此时引用计数不为0，或blocked标志位不为0，则该函数到此结束；
     * 到此，即ngx_http_close_request方法的功能只是将原始请求引用计数减1；
     */
    if (r->count || r->blocked) {
        return;
    }

#if (NGX_HTTP_SPDY)
    if (r->spdy_stream) {
        ngx_http_spdy_close_stream(r->spdy_stream, rc);
        return;
    }
#endif

    /*
     * 若引用计数此时为0（表示请求没有其他动作要使用），
     * 且blocked也为0（表示没有HTTP模块还需要处理请求），
     * 则调用ngx_http_free_request释放请求所对应的结构体ngx_http_request_t，
     * 调用ngx_http_close_connection关闭当前连接；
     */
    ngx_http_free_request(r, rc);
    ngx_http_close_connection(c);
}

ngx_http_free_request 函数的执行流程：
调用当前请求的 cleanup 链表的回调方法 handler 开始清理工作释放资源；
在 HTTP 的 NGX_HTTP_LOG_PHASE 阶段调用所有回调方法记录日志；
调用 ngx_destroy_pool 方法销毁保存请求结构ngx_http_request_t 的内存池pool；
/* 释放当前请求 ngx_http_request_t 的数据结构 */
void
ngx_http_free_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_log_t                 *log;
    ngx_pool_t                *pool;
    struct linger              linger;
    ngx_http_cleanup_t        *cln;
    ngx_http_log_ctx_t        *ctx;
    ngx_http_core_loc_conf_t  *clcf;

    log = r->connection->log;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0, "http close request");

    if (r->pool == NULL) {
        ngx_log_error(NGX_LOG_ALERT, log, 0, "http request already closed");
        return;
    }

    /* 获取当前请求的清理cleanup方法 */
    cln = r->cleanup;
    r->cleanup = NULL;

    /* 调用清理方法cleanup的回调方法handler开始清理工作 */
    while (cln) {
        if (cln->handler) {
            cln->handler(cln->data);
        }

        cln = cln->next;
    }

#if (NGX_STAT_STUB)

    if (r->stat_reading) {
        (void) ngx_atomic_fetch_add(ngx_stat_reading, -1);
    }

    if (r->stat_writing) {
        (void) ngx_atomic_fetch_add(ngx_stat_writing, -1);
    }

#endif

    /* 记录日志 */
    if (rc > 0 && (r->headers_out.status == 0 || r->connection->sent == 0)) {
        r->headers_out.status = rc;
    }

    log->action = "logging request";

    ngx_http_log_request(r);

    log->action = "closing request";

    if (r->connection->timedout) {
        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

        if (clcf->reset_timedout_connection) {
            linger.l_onoff = 1;
            linger.l_linger = 0;

            if (setsockopt(r->connection->fd, SOL_SOCKET, SO_LINGER,
                           (const void *) &linger, sizeof(struct linger)) == -1)
            {
                ngx_log_error(NGX_LOG_ALERT, log, ngx_socket_errno,
                              "setsockopt(SO_LINGER) failed");
            }
        }
    }

    /* the various request strings were allocated from r->pool */
    ctx = log->data;
    ctx->request = NULL;

    r->request_line.len = 0;

    r->connection->destroyed = 1;

    /*
     * Setting r->pool to NULL will increase probability to catch double close
     * of request since the request object is allocated from its own pool.
     */

    pool = r->pool;
    r->pool = NULL;

    /* 销毁请求ngx_http_request_t 所对应的内存池 */
    ngx_destroy_pool(pool);
}

ngx_http_close_connection 函数的执行流程：
将当前连接的 destroyed 标志位设置为 1，表示即将销毁该连接；
调用 ngx_close_connection 方法开始销毁连接；
最后销毁该链接所使用的内存池 pool；
/* 关闭TCP连接 */
void
ngx_http_close_connection(ngx_connection_t *c)
{
    ngx_pool_t  *pool;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "close http connection: %d", c->fd);

#if (NGX_HTTP_SSL)

    if (c->ssl) {
        if (ngx_ssl_shutdown(c) == NGX_AGAIN) {
            c->ssl->handler = ngx_http_close_connection;
            return;
        }
    }

#endif

#if (NGX_STAT_STUB)
    (void) ngx_atomic_fetch_add(ngx_stat_active, -1);
#endif

    /* 设置当前连接的destroyed标志位为1，表示即将销毁该连接 */
    c->destroyed = 1;

    pool = c->pool;

    /* 关闭套接字连接 */
    ngx_close_connection(c);

    /* 销毁连接所使用的内存池 */
    ngx_destroy_pool(pool);
}

ngx_close_connection 函数的执行流程：
检查读、写事件的 timer_set 标志位，若该标志位都为1，则调用ngx_del_timer 方法将读、写事件从定时器机制中移除；
若定义了 ngx_del_conn 宏调用 ngx_del_conn 方法将当前连接上的读、写事件从 epoll 事件机制中移除，若没定义ngx_del_conn 宏，则调用ngx_del_event 方法将读、写事件从epoll 事件机制中移除；
调用 ngx_free_connection 方法释放当前连接结构；
调用 ngx_close_socket 方法关闭套接字连接；
/* 关闭套接字连接 */
void
ngx_close_connection(ngx_connection_t *c)
{
    ngx_err_t     err;
    ngx_uint_t    log_error, level;
    ngx_socket_t  fd;

    if (c->fd == (ngx_socket_t) -1) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0, "connection already closed");
        return;
    }

    /* 将当前连接的读、写事件从定时器机制中移除 */
    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

    /* 将当前连接的读、写事件从epoll事件机制中移除 */
    if (ngx_del_conn) {
        ngx_del_conn(c, NGX_CLOSE_EVENT);

    } else {
        if (c->read->active || c->read->disabled) {
            ngx_del_event(c->read, NGX_READ_EVENT, NGX_CLOSE_EVENT);
        }

        if (c->write->active || c->write->disabled) {
            ngx_del_event(c->write, NGX_WRITE_EVENT, NGX_CLOSE_EVENT);
        }
    }

#if (NGX_THREADS)

    /*
     * we have to clean the connection information before the closing
     * because another thread may reopen the same file descriptor
     * before we clean the connection
     */

    ngx_mutex_lock(ngx_posted_events_mutex);

    if (c->read->prev) {
        ngx_delete_posted_event(c->read);
    }

    if (c->write->prev) {
        ngx_delete_posted_event(c->write);
    }

    c->read->closed = 1;
    c->write->closed = 1;

    ngx_unlock(&c->lock);
    c->read->locked = 0;
    c->write->locked = 0;

    ngx_mutex_unlock(ngx_posted_events_mutex);

#else

    if (c->read->prev) {
        ngx_delete_posted_event(c->read);
    }

    if (c->write->prev) {
        ngx_delete_posted_event(c->write);
    }

    c->read->closed = 1;
    c->write->closed = 1;

#endif

    ngx_reusable_connection(c, 0);

    log_error = c->log_error;

    /* 释放当前连接结构体 */
    ngx_free_connection(c);

    fd = c->fd;
    c->fd = (ngx_socket_t) -1;

    /* 关闭套接字连接 */
    if (ngx_close_socket(fd) == -1) {

        err = ngx_socket_errno;

        if (err == NGX_ECONNRESET || err == NGX_ENOTCONN) {

            switch (log_error) {

            case NGX_ERROR_INFO:
                level = NGX_LOG_INFO;
                break;

            case NGX_ERROR_ERR:
                level = NGX_LOG_ERR;
                break;

            default:
                level = NGX_LOG_CRIT;
            }

        } else {
            level = NGX_LOG_CRIT;
        }

        /* we use ngx_cycle->log because c->log was in c->pool */

        ngx_log_error(level, ngx_cycle->log, err,
                      ngx_close_socket_n " %d failed", fd);
    }
}

ngx_http_terminate_request 函数的执行流程：
调用原始请求的 cleanup 链表的回调方法 handler 开始清理工作；
调用 ngx_http_close_request 方法关闭请求；
/* 强制关闭连接 */
static void
ngx_http_terminate_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_http_cleanup_t    *cln;
    ngx_http_request_t    *mr;
    ngx_http_ephemeral_t  *e;

    mr = r->main;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http terminate request count:%d", mr->count);

    if (rc > 0 && (mr->headers_out.status == 0 || mr->connection->sent == 0)) {
        mr->headers_out.status = rc;
    }

    /* 调用原始请求的cleanup的回调方法，开始清理工作 */
    cln = mr->cleanup;
    mr->cleanup = NULL;

    while (cln) {
        if (cln->handler) {
            cln->handler(cln->data);
        }

        cln = cln->next;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http terminate cleanup count:%d blk:%d",
                   mr->count, mr->blocked);

    if (mr->write_event_handler) {

        if (mr->blocked) {
            return;
        }

        e = ngx_http_ephemeral(mr);
        mr->posted_requests = NULL;
        mr->write_event_handler = ngx_http_terminate_handler;
        (void) ngx_http_post_request(mr, &e->terminal_posted_request);
        return;
    }

    /* 释放请求，并关闭连接 */
    ngx_http_close_request(mr, rc);
}
