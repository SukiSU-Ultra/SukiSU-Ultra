package com.sukisu.ultra.data.repository

import com.sun.net.httpserver.HttpServer
import java.net.InetSocketAddress
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.io.Closeable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.junit.Assert.*
import org.junit.Test

class ThemeStoreAccessTest {
    private class Memory : ThemeAccessStore {
        val rows=mutableMapOf<String,String>()
        override fun get(key: String)=rows[key]
        override fun put(key: String,value: String?): Boolean { if(value==null)rows.remove(key) else rows[key]=value;return true }
    }
    private class Server(private val callback:(String,String,String?)->Pair<Int,String>) : Closeable {
        private val executor=Executors.newCachedThreadPool()
        private val http=HttpServer.create(InetSocketAddress("127.0.0.1",0),0).apply {
            this.executor=this@Server.executor
            createContext("/") { exchange ->
                exchange.use {
                    val (code,text)=callback(it.requestURI.path,it.requestBody.readAllBytes().toString(Charsets.UTF_8),it.requestHeaders.getFirst("Authorization"))
                    val bytes=text.toByteArray();it.responseHeaders.set("Content-Type","application/json");it.sendResponseHeaders(code,bytes.size.toLong());it.responseBody.write(bytes)
                }
            }
            start()
        }
        val url get()="http://127.0.0.1:"+http.address.port+"/"
        override fun close(){http.stop(0);executor.shutdownNow()}
    }
    private fun credential(time:Long,number:Int=1)=DeviceAccess("sa_"+number.toString(16).repeat(64),"sr_"+number.toString(16).repeat(64),time+900,time+86400)
    private fun encoded(value:DeviceAccess)=Json.encodeToString(value)

    @Test fun bootstrapsAndRotatesOnceAcrossConcurrentRepositories() {
        val clock=AtomicLong(1000);val calls=AtomicInteger();val memory=Memory()
        Server { route,body,auth ->
            val call=calls.incrementAndGet();assertNull(auth)
            if(call==1)assertEquals("/client/access",route) else {assertEquals("/client/refresh",route);assertTrue(body.contains("sr_"+"1".repeat(64)))}
            200 to encoded(credential(clock.get(),call))
        }.use { server ->
            val first=ThemeStoreAccessRepository(memory,{null},now={clock.get()});val second=ThemeStoreAccessRepository(memory,{null},now={clock.get()})
            assertEquals(credential(1000).accessToken,first.resolve(server.url,""))
            clock.addAndGet(800)
            val pool=Executors.newFixedThreadPool(6)
            try { val results=(0..5).map { pool.submit<String> { second.resolve(server.url,"") } }.map {it.get()};assertTrue(results.all {it==credential(1800,2).accessToken});assertEquals(2,calls.get()) } finally {pool.shutdownNow()}
            assertEquals(credential(1800,2).accessToken,ThemeStoreAccessRepository.currentForUrl(server.url+"previews/a.png",credential(1000).accessToken))
        }
    }
    @Test fun bootstrapBindsAccountButRefreshNeverForwardsAccountSecret() {
        val clock=AtomicLong(1000);val calls=AtomicInteger()
        Server { route,_,auth -> if(calls.incrementAndGet()==1){assertEquals("/client/access",route);assertEquals("Bearer account-secret",auth)}else{assertEquals("/client/refresh",route);assertNull(auth)};200 to encoded(credential(clock.get(),calls.get())) }.use { server ->
            val provider=ThemeStoreAccessRepository(Memory(),{"owner" to "account-secret"},now={clock.get()})
            provider.resolve(server.url,"");clock.addAndGet(800);provider.resolve(server.url,"");assertEquals(2,calls.get())
        }
    }
    @Test fun revokedRefreshRequiresExplicitReauthorization() {
        val clock=AtomicLong(1000);val calls=AtomicInteger();val memory=Memory()
        Server { _,_,_ -> if(calls.incrementAndGet()==1)200 to encoded(credential(clock.get())) else 401 to "{}" }.use { server ->
            val provider=ThemeStoreAccessRepository(memory,{null},now={clock.get()});provider.resolve(server.url,"");clock.addAndGet(800)
            repeat(2){try{provider.resolve(server.url,"");fail("revoked credential accepted")}catch(_:ThemeStoreUnauthorizedException){}}
            assertEquals(2,calls.get());provider.reset(server.url);assertTrue(memory.rows.isEmpty())
        }
    }
    @Test fun rejectsRedirectsAndDoesNotForwardSecretsToAnotherEndpoint() {
        val seen=AtomicInteger()
        Server { _,_,_ -> seen.incrementAndGet();200 to encoded(credential(1000)) }.use { destination ->
            val http=HttpServer.create(InetSocketAddress("127.0.0.1",0),0)
            http.createContext("/"){it.responseHeaders.set("Location",destination.url);it.sendResponseHeaders(307,-1);it.close()};http.start()
            try{val provider=ThemeStoreAccessRepository(Memory(),{"owner" to "secret"},now={1000});try{provider.resolve("http://127.0.0.1:"+http.address.port+"/","");fail("redirect followed")}catch(_:java.io.IOException){};assertEquals(0,seen.get())}finally{http.stop(0)}
        }
    }
    @Test fun rejectsInsecureEndpointsAndOversizedCredentialResponses() {
        val provider=ThemeStoreAccessRepository(Memory(),{null},now={1000})
        try{provider.resolve("http://example.com/","");fail("cleartext credential allowed")}catch(_:java.io.IOException){}
        Server { _,_,_ ->200 to "x".repeat(65537) }.use {server->try{provider.resolve(server.url,"");fail("oversize response accepted")}catch(_:java.io.IOException){}}
    }
    @Test fun preservesExplicitScriptTokensWithoutBootstrapping() {
        val provider=ThemeStoreAccessRepository(Memory(),{null},now={1000})
        assertEquals("explicit-script-token",provider.resolve("https://example.com/","explicit-script-token"))
    }

    @Test fun neverAttachesImportedJsonOrRefreshSecretsToAssetHeaders() {
        val provider=ThemeStoreAccessRepository(Memory(),{null},now={1000})
        val url="https://unresolved.example/themes/a.sukisu"
        for (secret in listOf("{\"token\":\"sa_abc\",\"refreshToken\":\"sr_private\"}","sr_"+"a".repeat(64))) {
            assertEquals("",ThemeStoreAccessRepository.currentForUrl(url,secret))
            try { provider.forRequest(url,secret);fail("refresh material reached an asset request") } catch (_:java.io.IOException) {}
        }
    }
}
