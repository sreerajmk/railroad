#pragma once

#include <functional>
#include <initializer_list>
#include <utility>
#include <stdexcept>
#include <cstddef>
#include <iterator>

// This file is an educational red-black tree style map skeleton.
// A real std::map in the standard library is usually implemented as a
// balanced binary search tree, and a common choice is a red-black tree.
// The structure below keeps the same public shape as a simple map while
// storing nodes with left/right/parent pointers and an explicit color field.
// The balancing operations are organized in the same style used by classic
// red-black tree algorithms: rotateLeft, rotateRight, recolor, fixInsert,
// and fixRemove. This makes the tree self-balancing on insert and erase.

namespace clibs {

    template <typename Key, typename T, typename Compare = std::less<Key>>
    class Map {
    public:
        using key_type = Key;
        using mapped_type = T;
        using value_type = std::pair<Key, T>;

    private:
        enum class Color { Red, Black };

        struct Node {
            value_type entry;
            Node* left;
            Node* right;
            Node* parent;
            Color color;

            Node(const Key& key, const T& value, Node* p = nullptr, Color c = Color::Red)
                : entry(value_type(key, value)), left(nullptr), right(nullptr), parent(p), color(c) {}

            Node(Key&& key, T&& value, Node* p = nullptr, Color c = Color::Red)
                : entry(value_type(std::move(key), std::move(value))), left(nullptr), right(nullptr), parent(p), color(c) {}
        };

        Node* root_;
        Compare comp_;
        std::size_t size_;

    public:
        class iterator {
        public:
            using iterator_category = std::bidirectional_iterator_tag;
            using value_type = Map::value_type;
            using difference_type = std::ptrdiff_t;
            using pointer = value_type*;
            using reference = value_type&;

            iterator(Node* n = nullptr) : node_(n) {}

            reference operator*() const {
                return node_->entry;
            }

            pointer operator->() const {
                return &node_->entry;
            }

            iterator& operator++() {
                if (!node_) return *this;
                if (node_->right) {
                    node_ = minimum(node_->right);
                } else {
                    Node* child = node_;
                    node_ = node_->parent;
                    while (node_ && node_->right == child) {
                        child = node_;
                        node_ = node_->parent;
                    }
                }
                return *this;
            }

            iterator operator++(int) {
                iterator tmp = *this;
                ++(*this);
                return tmp;
            }

            iterator& operator--() {
                if (!node_) {
                    node_ = maximum(root_);
                } else if (node_->left) {
                    node_ = maximum(node_->left);
                } else {
                    Node* child = node_;
                    node_ = node_->parent;
                    while (node_ && node_->left == child) {
                        child = node_;
                        node_ = node_->parent;
                    }
                }
                return *this;
            }

            iterator operator--(int) {
                iterator tmp = *this;
                --(*this);
                return tmp;
            }

            bool operator==(const iterator& other) const {
                return node_ == other.node_;
            }

            bool operator!=(const iterator& other) const {
                return node_ != other.node_;
            }

        private:
            Node* node_;

            static Node* minimum(Node* n) {
                while (n && n->left) n = n->left;
                return n;
            }

            static Node* maximum(Node* n) {
                while (n && n->right) n = n->right;
                return n;
            }

            friend class Map;
        };

        explicit Map(const Compare& comp = Compare()) : root_(nullptr), comp_(comp), size_(0) {}

        Map(std::initializer_list<value_type> init, const Compare& comp = Compare()) : Map(comp) {
            for (const auto& item : init) insert(item);
        }

        ~Map() {
            clear();
        }

        Map(const Map&) = delete;
        Map& operator=(const Map&) = delete;

        std::pair<iterator, bool> insert(const value_type& pair) {
            return insertImpl(pair.first, pair.second);
        }

        template <typename K, typename V>
        std::pair<iterator, bool> insert(K&& key, V&& value) {
            return insertImpl(std::forward<K>(key), std::forward<V>(value));
        }

        T& operator[](const Key& key) {
            Node* n = findNode(root_, key);
            if (n) return n->entry.second;
            auto result = insertImpl(key, T{});
            return result.first->second;
        }

        T& at(const Key& key) {
            Node* n = findNode(root_, key);
            if (!n) throw std::out_of_range("key not found");
            return n->entry.second;
        }

        const T& at(const Key& key) const {
            Node* n = findNode(root_, key);
            if (!n) throw std::out_of_range("key not found");
            return n->entry.second;
        }

        iterator find(const Key& key) {
            return iterator(findNode(root_, key));
        }

        std::size_t erase(const Key& key) {
            Node* victim = findNode(root_, key);
            if (!victim) return 0;
            deleteNode(victim);
            --size_;
            return 1;
        }

        iterator erase(iterator it) {
            if (it == end()) return end();
            Node* next = successor(it.node_);
            erase(it.node_->entry.first);
            return iterator(next);
        }

        iterator begin() {
            return iterator(minimum(root_));
        }

        iterator end() {
            return iterator(nullptr);
        }

        std::size_t size() const {
            return size_;
        }

        bool empty() const {
            return size_ == 0;
        }

        void clear() {
            clearSubtree(root_);
            root_ = nullptr;
            size_ = 0;
        }

    private:
        template <typename K, typename V>
        std::pair<iterator, bool> insertImpl(K&& key, V&& value) {
            Node* parent = nullptr;
            Node* cursor = root_;

            while (cursor) {
                parent = cursor;
                if (comp_(key, cursor->entry.first)) {
                    cursor = cursor->left;
                } else if (comp_(cursor->entry.first, key)) {
                    cursor = cursor->right;
                } else {
                    return {iterator(cursor), false};
                }
            }

            Node* node = new Node(std::forward<K>(key), std::forward<V>(value), parent, Color::Red);
            if (!parent) {
                root_ = node;
            } else if (comp_(node->entry.first, parent->entry.first)) {
                parent->left = node;
            } else {
                parent->right = node;
            }

            fixInsert(node);
            root_->color = Color::Black;
            ++size_;
            return {iterator(node), true};
        }

        static Node* minimum(Node* n) {
            while (n && n->left) n = n->left;
            return n;
        }

        static Node* maximum(Node* n) {
            while (n && n->right) n = n->right;
            return n;
        }

        static Node* successor(Node* n) {
            if (!n) return nullptr;
            if (n->right) return minimum(n->right);
            Node* parent = n->parent;
            while (parent && parent->right == n) {
                n = parent;
                parent = parent->parent;
            }
            return parent;
        }

        Node* findNode(Node* n, const Key& key) const {
            while (n) {
                if (!comp_(key, n->entry.first) && !comp_(n->entry.first, key)) return n;
                if (comp_(key, n->entry.first)) n = n->left;
                else n = n->right;
            }
            return nullptr;
        }

        void rotateLeft(Node* x) {
            Node* y = x->right;
            x->right = y->left;
            if (y->left) y->left->parent = x;
            y->parent = x->parent;
            if (!x->parent) root_ = y;
            else if (x == x->parent->left) x->parent->left = y;
            else x->parent->right = y;
            y->left = x;
            x->parent = y;
        }

        void rotateRight(Node* x) {
            Node* y = x->left;
            x->left = y->right;
            if (y->right) y->right->parent = x;
            y->parent = x->parent;
            if (!x->parent) root_ = y;
            else if (x == x->parent->right) x->parent->right = y;
            else x->parent->left = y;
            y->right = x;
            x->parent = y;
        }

        void fixInsert(Node* node) {
            while (node != root_ && node->parent && node->parent->color == Color::Red) {
                Node* parent = node->parent;
                Node* grandparent = parent->parent;

                if (!grandparent) break;

                if (parent == grandparent->left) {
                    Node* uncle = grandparent->right;
                    if (uncle && uncle->color == Color::Red) {
                        parent->color = Color::Black;
                        uncle->color = Color::Black;
                        grandparent->color = Color::Red;
                        node = grandparent;
                    } else {
                        if (node == parent->right) {
                            node = parent;
                            rotateLeft(parent);
                            parent = node->parent;
                            grandparent = parent->parent;
                        }
                        parent->color = Color::Black;
                        grandparent->color = Color::Red;
                        rotateRight(grandparent);
                    }
                } else {
                    Node* uncle = grandparent->left;
                    if (uncle && uncle->color == Color::Red) {
                        parent->color = Color::Black;
                        uncle->color = Color::Black;
                        grandparent->color = Color::Red;
                        node = grandparent;
                    } else {
                        if (node == parent->left) {
                            node = parent;
                            rotateRight(parent);
                            parent = node->parent;
                            grandparent = parent->parent;
                        }
                        parent->color = Color::Black;
                        grandparent->color = Color::Red;
                        rotateLeft(grandparent);
                    }
                }
            }
        }

        void deleteNode(Node* victim) {
            Node* replacement = victim;
            Node* child = nullptr;
            Color originalColor = replacement->color;

            if (!victim->left) {
                child = victim->right;
                transplant(victim, child);
            } else if (!victim->right) {
                child = victim->left;
                transplant(victim, child);
            } else {
                replacement = minimum(victim->right);
                originalColor = replacement->color;
                child = replacement->right;
                if (replacement->parent == victim) {
                    child->parent = replacement;
                } else {
                    transplant(replacement, replacement->right);
                    replacement->right = victim->right;
                    replacement->right->parent = replacement;
                }
                transplant(victim, replacement);
                replacement->left = victim->left;
                replacement->left->parent = replacement;
                replacement->color = victim->color;
            }

            if (originalColor == Color::Black) {
                fixDelete(child, replacement != victim ? replacement->parent : victim->parent);
            }

            delete victim;
        }

        void transplant(Node* u, Node* v) {
            if (!u->parent) {
                root_ = v;
            } else if (u == u->parent->left) {
                u->parent->left = v;
            } else {
                u->parent->right = v;
            }
            if (v) v->parent = u->parent;
        }

        void fixDelete(Node* x, Node* parent) {
            while (x != root_ && (!x || x->color == Color::Black)) {
                if (x == parent->left) {
                    Node* w = parent->right;
                    if (w->color == Color::Red) {
                        w->color = Color::Black;
                        parent->color = Color::Red;
                        rotateLeft(parent);
                        w = parent->right;
                    }
                    if ((!w->left || w->left->color == Color::Black) &&
                        (!w->right || w->right->color == Color::Black)) {
                        w->color = Color::Red;
                        x = parent;
                        parent = parent->parent;
                    } else {
                        if (!w->right || w->right->color == Color::Black) {
                            if (w->left) w->left->color = Color::Black;
                            w->color = Color::Red;
                            rotateRight(w);
                            w = parent->right;
                        }
                        w->color = parent->color;
                        parent->color = Color::Black;
                        if (w->right) w->right->color = Color::Black;
                        rotateLeft(parent);
                        x = root_;
                    }
                } else {
                    Node* w = parent->left;
                    if (w->color == Color::Red) {
                        w->color = Color::Black;
                        parent->color = Color::Red;
                        rotateRight(parent);
                        w = parent->left;
                    }
                    if ((!w->left || w->left->color == Color::Black) &&
                        (!w->right || w->right->color == Color::Black)) {
                        w->color = Color::Red;
                        x = parent;
                        parent = parent->parent;
                    } else {
                        if (!w->left || w->left->color == Color::Black) {
                            if (w->right) w->right->color = Color::Black;
                            w->color = Color::Red;
                            rotateLeft(w);
                            w = parent->left;
                        }
                        w->color = parent->color;
                        parent->color = Color::Black;
                        if (w->left) w->left->color = Color::Black;
                        rotateRight(parent);
                        x = root_;
                    }
                }
            }
            if (x) x->color = Color::Black;
        }

        void clearSubtree(Node* node) {
            if (!node) return;
            clearSubtree(node->left);
            clearSubtree(node->right);
            delete node;
        }
    };
}
