TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += main.cpp \
    nfc_verify.cpp \
    sm4_test.cpp \
    src/sm/sm4.c \
    verify_server.cpp \
    proxy_manager.cpp \
    src/threadpool.c \
    threadpool.c

include(deployment.pri)
qtcAddDeployment()

HEADERS += \
    inc/sm/sm4.h \
    inc/event2/buffer.h \
    inc/event2/buffer_compat.h \
    inc/event2/bufferevent.h \
    inc/event2/bufferevent_compat.h \
    inc/event2/bufferevent_ssl.h \
    inc/event2/bufferevent_struct.h \
    inc/event2/dns.h \
    inc/event2/dns_compat.h \
    inc/event2/dns_struct.h \
    inc/event2/event-config.h \
    inc/event2/event.h \
    inc/event2/event_compat.h \
    inc/event2/event_struct.h \
    inc/event2/http.h \
    inc/event2/http_compat.h \
    inc/event2/http_struct.h \
    inc/event2/keyvalq_struct.h \
    inc/event2/listener.h \
    inc/event2/rpc.h \
    inc/event2/rpc_compat.h \
    inc/event2/rpc_struct.h \
    inc/event2/tag.h \
    inc/event2/tag_compat.h \
    inc/event2/thread.h \
    inc/event2/util.h \
    verify_server.h \
    proxy_manager.h \
    event2/buffer.h \
    event2/buffer_compat.h \
    event2/bufferevent.h \
    event2/bufferevent_compat.h \
    event2/bufferevent_ssl.h \
    event2/bufferevent_struct.h \
    event2/dns.h \
    event2/dns_compat.h \
    event2/dns_struct.h \
    event2/event-config.h \
    event2/event.h \
    event2/event_compat.h \
    event2/event_struct.h \
    event2/http.h \
    event2/http_compat.h \
    event2/http_struct.h \
    event2/keyvalq_struct.h \
    event2/listener.h \
    event2/rpc.h \
    event2/rpc_compat.h \
    event2/rpc_struct.h \
    event2/tag.h \
    event2/tag_compat.h \
    event2/thread.h \
    event2/util.h \
    inc/threadpool.h \
    threadpool.h

