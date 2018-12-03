/*
 * This is part of the "Access Control Delegation for the Internet of Things" project
 * Author: ControlThingsOpenSource
 * More info: https://www.contronthings.gr https://github.com/ControlThingsOpenSource/Access-Control
 */
package gr.controlthings.httpserver;

import com.sun.net.httpserver.*;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import gr.controlthings.core.CTCore;

public class CTServer {
    /*
    0xf8a1d7b266d9a06f0888839b87c4d63474d4727b
    */

    public static void main(String[] args) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(9000), 0);
        server.createContext("/simple", new SimpleHandler());
        server.setExecutor(null); // creates a default executor
        server.start();
    }
    
    static class SimpleHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange httpExchange) throws IOException {
            httpExchange.getResponseHeaders().add("Access-Control-Allow-Origin","*");
            httpExchange.getResponseHeaders().add("Access-Control-Allow-Headers","*");
            if (httpExchange.getRequestMethod().equalsIgnoreCase("OPTIONS"))
            {
                httpExchange.sendResponseHeaders(200,0);
                httpExchange.close();
                return;
            }
            System.out.println("Method " + httpExchange.getRequestMethod() + " " + httpExchange.getRequestURI() );
            String query = httpExchange.getRequestURI().getQuery();
            if (query == null)
            {
                System.out.println("Did not receive token " );
                String response = "{\"token\":\"" + CTCore.createRandomToken64() +"\",\"ACP\":\"" + CTCore.ACL.get("mmlab.edu.gr") + "\"}";
                httpExchange.sendResponseHeaders(404,response.length());
                OutputStream os = httpExchange.getResponseBody();
                os.write(response.getBytes());
                os.close();
            }
            else
            {
                System.out.println("Received token " );
                String measurement = "{value:34}"; 
                String token   = query;
                System.out.println("Received token " + token);
                String response    = "{\"data\":\"" + CTCore.encryptData64(token, measurement.getBytes()) + "\"}";
                httpExchange.sendResponseHeaders(200,response.length());
                OutputStream os = httpExchange.getResponseBody();
                os.write(response.getBytes());
                os.close();
            }
            /*
            String response = "This is the response";
            t.sendResponseHeaders(200, response.length());
            OutputStream os = t.getResponseBody();
            os.write(response.getBytes());
            os.close();
            */
        }
    }
    
}
