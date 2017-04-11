angular.module('starter.controllers', [])

  .controller('DashCtrl', function ($scope, $auth) {
    var vm = this;
    vm.loading = true;
    vm.loging_status = 'loging_status';
    vm.logout = function () {
      $auth.signOut();
    }

    vm.login = function (user) {
      vm.loging_status = 'Starting request';
      $auth.signInWithCredentials(user.username, user.password).then(function(){
        vm.loging_status = 'Logged in..';
      }, function(result){
        vm.loging_status = JSON.stringify(result);
      });
    }

    vm.isAuthed = function () {
      return $auth.isAuthenticated();
    }
  })

  .controller('ChatsCtrl', function ($scope, Chats) {
    // With the new view caching in Ionic, Controllers are only called
    // when they are recreated or on app start, instead of every page change.
    // To listen for when this page is active (for example, to refresh data),
    // listen for the $ionicView.enter event:
    //
    //$scope.$on('$ionicView.enter', function(e) {
    //});

    $scope.chats = Chats.all();
    $scope.remove = function (chat) {
      Chats.remove(chat);
    };
  })

  .controller('ChatDetailCtrl', function ($scope, $stateParams, Chats) {
    $scope.chat = Chats.get($stateParams.chatId);
  })

  .controller('AccountCtrl', function ($scope) {
    $scope.settings = {
      enableFriends: true
    };
  });
