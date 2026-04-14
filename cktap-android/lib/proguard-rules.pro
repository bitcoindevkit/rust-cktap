# for JNA
-dontwarn java.awt.*
-keep class com.sun.jna.* { *; }
-keep class com.coinkite.cktap.* { *; }
-keepclassmembers class * extends com.coinkite.cktap.* { public *; }
-keepclassmembers class * extends com.sun.jna.* { public *; }
