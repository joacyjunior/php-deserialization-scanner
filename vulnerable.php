<?php
// Lab de Desserialização Insegura
// Simula uma aplicação que guarda preferências em um cookie serializado

class UserProfile {
    public $name;
    public $theme;
    public function __construct($n, $t) { $this->name = $n; $this->theme = $t; }
}

// Lógica de Identificação
if (isset($_COOKIE['user_prefs'])) {
    // A vulnerabilidade está aqui
    $data = base64_decode($_COOKIE['user_prefs']);
    $profile = unserialize($data); 
    
    if ($profile) {
        echo "<h1>Bem-vindo, " . htmlspecialchars($profile->name) . "!</h1>";
    }
} else {
    $default = new UserProfile("Visitante", "dark");
    setcookie("user_prefs", base64_encode(serialize($default)));
    echo "<h1>Cookie de sessão criado. Recarregue a página para testar o scanner.</h1>";
}

// Pista proposital para o scanner encontrar
echo "<!-- DEBUG: Serialized prefs used -->";
?>