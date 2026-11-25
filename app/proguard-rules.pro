# Правила проекта. Compose, корутины и DataStore поставляют свои consumer-
# правила; прежние сплошные -keep на androidx.compose.**, kotlinx.coroutines.**
# и androidx.datastore.** запрещали R8 вырезать неиспользуемый код (dex ~5.7 МБ).

# JNI: имена native-методов должны совпадать с экспортами libtgwsproxy.so.
-keepclasseswithmembernames,includedescriptorclasses class * {
    native <methods>;
}
-keep class com.amurcanov.tgwsproxy.NativeProxy { *; }
