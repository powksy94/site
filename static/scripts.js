const currentUrl = window.location.href;
const isLocalhost = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1';
const referer = document.referrer;

document.getElementById('dev_monitor').addEventListener('click', function () {
  const jwtToken = localStorage.getItem('jwt_token');
  
  if (jwtToken && isLocalhost) {
    if (referer.includes("/Homepage.html")) {
      fetch('/api/user', {
        method: 'GET',
        headers: {
          'Authorization': 'Bearer ' + jwtToken
        }
      })
        .then(response => {
          if (response.ok) {
            return response.json();
          } else {
            throw new Error('Jeton invalide ou session expirée');
          }
        })
        .then(data => {
          console.log(data);
        })
        .catch(error => {
          console.error('Erreur:', error);
          document.getElementById('user-info').innerText = 'Erreur lors de la récupération des informations.';
        });
    } else {
      window.location.href = '/';
    }
  } else {
    if (!jwtToken) {
      document.getElementById('user-info').innerText = 'Vous devez être connecté pour voir vos informations.';
    } else if (!isLocalhost) {
      document.getElementById('user-info').innerText = 'Accès non autorisé. Cette fonctionnalité est réservée à la machine locale.';
    }
  }
});

async function checkUserRole() {
  const jwtToken = localStorage.getItem('jwt_token');
  const isLocalhost = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1';

  // Vérification du token
  if (!jwtToken) {
    alert('Jeton manquant');
    window.location.href = '/login';
    return;
  }

  try {
    // Requête pour récupérer les données de l'utilisateur
    const response = await fetch('/api/user', {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${jwtToken}`
      }
    });

    // Vérification des réponses de l'API
    if (!response.ok) {
      if (response.status === 401) {
        alert('Non autorisé. Vous devez vous connecter.');
        window.location.href = '/login';
        return;
      }
      throw new Error('Échec de la récupération des données utilisateur!');
    }

    const userData = await response.json();

    // Vérification du rôle et de l'emplacement
    if (!isLocalhost) {
      alert("Accès refusé : Vous devez être sur la machine locale pour accéder à cette fonctionnalité.");
      window.location.href = '/Homepage.html';
    } else {
      console.log("Accès autorisé : utilisateur avec le rôle", userData.role);
    }

  } catch (error) {
    // Gestion des erreurs
    console.error('Erreur:', error);
    alert('Erreur lors de la vérification du rôle de l\'utilisateur.');
    window.location.href = '/login';
  }
}


document.getElementById('btn-dvlp').addEventListener('click', function () {
  const jwtToken = localStorage.getItem('jwt_token');
  const isLocalhost = location.hostname === "127.0.0.1" || location.hostname === "localhost";

  if (jwtToken || isLocalhost) {
    if (referer.includes("/Homepage.html")) {
      fetch('/analyze_data', {
        method: 'GET',
        headers: {
          'Authorization': jwtToken ? 'Bearer ' + jwtToken : ''
        }
      })
        .then(response => {
          if (response.ok) {
            return response.text();
          } else {
            throw new Error("Erreur de jeton ou permission");
          }
        })
        .then(htmlContent => {
          document.getElementById('user-info').innerHTML = htmlContent;
          // Rediriger après affichage si nécessaire
          // window.location.href = '/analyze_data';
        })
        .catch(error => {
          console.error("Erreur:", error);
          document.getElementById('user-info').innerText = 'Erreur lors de la récupération des informations.';
        });
    }
  } else {
    window.location.href = '/login.html';
  }
});

chekUserRole();

// Menu toggle
const menuToggle = document.querySelector('.menu-toggle');
const navLinks = document.querySelector('.nav-links');
menuToggle.addEventListener('click', () => {
  navLinks.classList.toggle('active');
  document.body.classList.toggle('menu-open');
});
